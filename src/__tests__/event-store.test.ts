/**
 * Unit tests for DefenseEventStore
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DefenseEventStore } from '../evolve/event-store';
import { DefenseEvent } from '../evolve/types';
import { RiskLevel } from '../types';

function makeTmpDir(): string {
  return path.join(os.tmpdir(), 'clawarmor-test-' + Date.now() + '-' + Math.random().toString(36).slice(2));
}

function makeEvent(overrides: Partial<DefenseEvent> = {}): DefenseEvent {
  return {
    id: 'evt-' + Math.random().toString(36).slice(2),
    timestamp: Date.now(),
    hookType: 'input',
    sessionId: 'session-1',
    input: 'test input',
    riskLevel: RiskLevel.NONE,
    detectedPatterns: [],
    blocked: false,
    ...overrides
  };
}

describe('DefenseEventStore', () => {
  let tmpDir: string;
  let dbPath: string;
  let store: DefenseEventStore;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    fs.mkdirSync(tmpDir, { recursive: true });
    dbPath = path.join(tmpDir, 'events.db');
    store = new DefenseEventStore(dbPath);
  });

  afterEach(async () => {
    await store.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // --- 初始化 ---
  describe('初始化', () => {
    it('init() 应成功创建存储并返回 0 条记录', async () => {
      await store.init();
      const count = await store.count();
      expect(count).toBe(0);
    });

    it('重复调用 init() 应是幂等的', async () => {
      await store.init();
      await store.init();
      const count = await store.count();
      expect(count).toBe(0);
    });
  });

  // --- 事件添加与查询 ---
  describe('事件添加与查询', () => {
    it('record() 后 count() 应增加', async () => {
      await store.init();
      await store.record(makeEvent({ id: 'e1' }));
      await store.record(makeEvent({ id: 'e2' }));
      expect(await store.count()).toBe(2);
    });

    it('getRecent() 应按插入顺序返回最新的事件', async () => {
      await store.init();
      const e1 = makeEvent({ id: 'e1', timestamp: 1000 });
      const e2 = makeEvent({ id: 'e2', timestamp: 2000 });
      await store.record(e1);
      await store.record(e2);
      const recent = await store.getRecent(10);
      // unshift → 最新在前
      expect(recent[0].id).toBe('e2');
      expect(recent[1].id).toBe('e1');
    });

    it('getRecent(limit) 应限制返回数量', async () => {
      await store.init();
      for (let i = 0; i < 5; i++) {
        await store.record(makeEvent({ id: `e${i}` }));
      }
      const recent = await store.getRecent(3);
      expect(recent.length).toBe(3);
    });

    it('getAll() 应返回所有事件', async () => {
      await store.init();
      for (let i = 0; i < 4; i++) {
        await store.record(makeEvent({ id: `e${i}` }));
      }
      const all = await store.getAll();
      expect(all.length).toBe(4);
    });

    it('getSince(timestamp) 应只返回该时间戳之后的事件', async () => {
      await store.init();
      const base = 1000000;
      await store.record(makeEvent({ id: 'old', timestamp: base }));
      await store.record(makeEvent({ id: 'new', timestamp: base + 1000 }));
      const results = await store.getSince(base);
      expect(results.length).toBe(1);
      expect(results[0].id).toBe('new');
    });
  });

  // --- 标记误报 / 漏报 ---
  describe('标记误报与漏报', () => {
    it('markFalsePositive() 应设置 falsePositive=true', async () => {
      await store.init();
      const evt = makeEvent({ id: 'fp-evt' });
      await store.record(evt);
      await store.markFalsePositive(['fp-evt']);
      const all = await store.getAll();
      expect(all.find(e => e.id === 'fp-evt')?.falsePositive).toBe(true);
    });

    it('markMissedAttack() 应设置 missedAttack=true', async () => {
      await store.init();
      const evt = makeEvent({ id: 'fn-evt' });
      await store.record(evt);
      await store.markMissedAttack(['fn-evt']);
      const all = await store.getAll();
      expect(all.find(e => e.id === 'fn-evt')?.missedAttack).toBe(true);
    });

    it('getFalsePositives() 应只返回标记为误报的事件', async () => {
      await store.init();
      await store.record(makeEvent({ id: 'fp' }));
      await store.record(makeEvent({ id: 'normal' }));
      await store.markFalsePositive(['fp']);
      const fps = await store.getFalsePositives();
      expect(fps.length).toBe(1);
      expect(fps[0].id).toBe('fp');
    });

    it('getMissedAttacks() 应只返回标记为漏报的事件', async () => {
      await store.init();
      await store.record(makeEvent({ id: 'fn' }));
      await store.record(makeEvent({ id: 'normal' }));
      await store.markMissedAttack(['fn']);
      const fns = await store.getMissedAttacks();
      expect(fns.length).toBe(1);
      expect(fns[0].id).toBe('fn');
    });
  });

  // --- 指标计算 ---
  describe('getMetrics()', () => {
    it('空存储应返回全零指标', async () => {
      await store.init();
      const metrics = await store.getMetrics();
      expect(metrics.totalEvents).toBe(0);
      expect(metrics.fpRate).toBe(0);
      expect(metrics.fnRate).toBe(0);
    });

    it('应正确计算 fpRate 和 fnRate', async () => {
      await store.init();
      // 4 events: 1 FP, 1 FN
      for (let i = 0; i < 4; i++) {
        await store.record(makeEvent({ id: `e${i}` }));
      }
      await store.markFalsePositive(['e0']);
      await store.markMissedAttack(['e1']);
      const metrics = await store.getMetrics();
      expect(metrics.totalEvents).toBe(4);
      expect(metrics.falsePositives).toBe(1);
      expect(metrics.falseNegatives).toBe(1);
      expect(metrics.fpRate).toBeCloseTo(0.25);
      expect(metrics.fnRate).toBeCloseTo(0.25);
    });

    it('blockedCount 应正确统计 blocked=true 的事件', async () => {
      await store.init();
      await store.record(makeEvent({ id: 'b1', blocked: true }));
      await store.record(makeEvent({ id: 'b2', blocked: true }));
      await store.record(makeEvent({ id: 'n1', blocked: false }));
      const metrics = await store.getMetrics();
      expect(metrics.blockedCount).toBe(2);
    });
  });

  // --- lastTriggeredCount 持久化 ---
  describe('lastTriggeredCount', () => {
    it('初始值应为 0', async () => {
      await store.init();
      expect(await store.getLastTriggeredCount()).toBe(0);
    });

    it('setLastTriggeredCount() 应持久化', async () => {
      await store.init();
      await store.setLastTriggeredCount(42);
      expect(await store.getLastTriggeredCount()).toBe(42);
    });
  });

  // --- 持久化到文件 / 重新加载 ---
  describe('持久化与重新加载', () => {
    it('关闭后重新打开应恢复原有事件', async () => {
      await store.init();
      await store.record(makeEvent({ id: 'persist-1' }));
      await store.record(makeEvent({ id: 'persist-2' }));
      await store.close();

      const store2 = new DefenseEventStore(dbPath);
      await store2.init();
      const count = await store2.count();
      expect(count).toBe(2);
      const ids = (await store2.getAll()).map(e => e.id).sort();
      expect(ids).toEqual(['persist-1', 'persist-2'].sort());
      await store2.close();
    });

    it('falsePositive 标记应在重新加载后保留', async () => {
      await store.init();
      await store.record(makeEvent({ id: 'fp-persist' }));
      await store.markFalsePositive(['fp-persist']);
      await store.close();

      const store2 = new DefenseEventStore(dbPath);
      await store2.init();
      const fps = await store2.getFalsePositives();
      expect(fps.length).toBe(1);
      expect(fps[0].id).toBe('fp-persist');
      await store2.close();
    });

    it('不存在的文件路径：init 后写入事件应创建父目录和文件', async () => {
      const nestedPath = path.join(tmpDir, 'nested', 'deep', 'events.db');
      const store3 = new DefenseEventStore(nestedPath);
      await store3.init();
      // record triggers save, which creates the file
      await store3.record(makeEvent({ id: 'nested-evt' }));
      expect(fs.existsSync(nestedPath)).toBe(true);
      await store3.close();
    });
  });
});
