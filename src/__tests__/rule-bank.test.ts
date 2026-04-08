/**
 * Unit tests for DefenseRuleBank
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DefenseRuleBank } from '../evolve/rule-bank';
import { DefenseRule, RuleStatus, RuleType } from '../evolve/types';
import { InjectionCategory } from '../types';

function makeTmpDir(): string {
  return path.join(os.tmpdir(), 'clawarmor-test-' + Date.now() + '-' + Math.random().toString(36).slice(2));
}

function makeRule(overrides: Partial<DefenseRule> = {}): DefenseRule {
  const now = Date.now();
  return {
    id: 'rule-' + Math.random().toString(36).slice(2),
    title: 'Test Rule',
    description: 'A test rule',
    pattern: 'test_pattern',
    type: RuleType.KEYWORD,
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    status: RuleStatus.SHADOW,
    createdAt: now,
    updatedAt: now,
    hitCount: 0,
    falsePositiveCount: 0,
    effectivenessScore: 0.5,
    source: 'manual',
    ...overrides
  };
}

describe('DefenseRuleBank', () => {
  let tmpDir: string;
  let rulesPath: string;
  let bank: DefenseRuleBank;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    fs.mkdirSync(tmpDir, { recursive: true });
    rulesPath = path.join(tmpDir, 'rules.json');
    bank = new DefenseRuleBank(rulesPath);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // --- 初始化与 Seed 规则 ---
  describe('初始化', () => {
    it('init() 应创建文件并加载 seed 规则', async () => {
      await bank.init();
      const rules = bank.getAllRules();
      expect(rules.length).toBeGreaterThan(0);
      expect(fs.existsSync(rulesPath)).toBe(true);
    });

    it('所有 seed 规则状态应为 SHADOW', async () => {
      await bank.init();
      const active = bank.getActiveRules();
      expect(active.length).toBe(0);
      const shadow = bank.getShadowRules();
      expect(shadow.length).toBeGreaterThan(0);
    });

    it('重复调用 init() 应是幂等的', async () => {
      await bank.init();
      const count1 = bank.getAllRules().length;
      await bank.init();
      const count2 = bank.getAllRules().length;
      expect(count1).toBe(count2);
    });
  });

  // --- addRule / addRules ---
  describe('规则添加', () => {
    it('addRule() 应将规则加入规则库', async () => {
      await bank.init();
      const rule = makeRule({ id: 'custom-1', status: RuleStatus.ACTIVE });
      await bank.addRule(rule);
      const found = bank.getRule('custom-1');
      expect(found).not.toBeNull();
      expect(found!.id).toBe('custom-1');
    });

    it('addRules() 应跳过重复 pattern（去重逻辑）', async () => {
      await bank.init();
      const before = bank.getAllRules().length;
      const dup1 = makeRule({ id: 'dup-1', pattern: 'UNIQUE_PATTERN_XYZ' });
      const dup2 = makeRule({ id: 'dup-2', pattern: 'unique_pattern_xyz' }); // same pattern, different case
      await bank.addRules([dup1, dup2]);
      const after = bank.getAllRules().length;
      // Only one of the two duplicates should be added
      expect(after).toBe(before + 1);
    });

    it('addRules() 对不同 pattern 应全部添加', async () => {
      await bank.init();
      const before = bank.getAllRules().length;
      const rules = [
        makeRule({ id: 'diff-1', pattern: 'pattern_alpha_111' }),
        makeRule({ id: 'diff-2', pattern: 'pattern_beta_222' })
      ];
      await bank.addRules(rules);
      expect(bank.getAllRules().length).toBe(before + 2);
    });
  });

  // --- KEYWORD 规则匹配 ---
  describe('KEYWORD 规则匹配', () => {
    it('match() 应匹配 ACTIVE KEYWORD 规则', async () => {
      await bank.init();
      const rule = makeRule({
        id: 'kw-active',
        pattern: 'dangerous,exploit',
        type: RuleType.KEYWORD,
        status: RuleStatus.ACTIVE
      });
      await bank.addRule(rule);
      const results = bank.match('this is a dangerous payload');
      const hit = results.find(r => r.ruleId === 'kw-active');
      expect(hit).toBeDefined();
      expect(hit!.matched).toBe(true);
    });

    it('match() 不应匹配 SHADOW KEYWORD 规则', async () => {
      await bank.init();
      const rule = makeRule({
        id: 'kw-shadow',
        pattern: 'dangerous,exploit',
        type: RuleType.KEYWORD,
        status: RuleStatus.SHADOW
      });
      await bank.addRule(rule);
      const results = bank.match('this is a dangerous payload');
      const hit = results.find(r => r.ruleId === 'kw-shadow');
      expect(hit).toBeUndefined();
    });

    it('matchShadow() 应匹配 SHADOW KEYWORD 规则', async () => {
      await bank.init();
      const rule = makeRule({
        id: 'kw-shadow2',
        pattern: 'dangerous,exploit',
        type: RuleType.KEYWORD,
        status: RuleStatus.SHADOW
      });
      await bank.addRule(rule);
      const results = bank.matchShadow('this is a dangerous payload');
      const hit = results.find(r => r.ruleId === 'kw-shadow2');
      expect(hit).toBeDefined();
      expect(hit!.matched).toBe(true);
    });

    it('matchShadow() 不应匹配 ACTIVE 规则', async () => {
      await bank.init();
      const rule = makeRule({
        id: 'kw-active2',
        pattern: 'dangerous,exploit',
        type: RuleType.KEYWORD,
        status: RuleStatus.ACTIVE
      });
      await bank.addRule(rule);
      const results = bank.matchShadow('this is a dangerous payload');
      const hit = results.find(r => r.ruleId === 'kw-active2');
      expect(hit).toBeUndefined();
    });

    it('KEYWORD 匹配应大小写不敏感', async () => {
      await bank.init();
      const rule = makeRule({
        id: 'kw-case',
        pattern: 'JAILBREAK',
        type: RuleType.KEYWORD,
        status: RuleStatus.ACTIVE
      });
      await bank.addRule(rule);
      const results = bank.match('try jailbreak the system');
      expect(results.find(r => r.ruleId === 'kw-case')).toBeDefined();
    });
  });

  // --- REGEX 规则匹配 ---
  describe('REGEX 规则匹配', () => {
    it('match() 应匹配 ACTIVE REGEX 规则', async () => {
      await bank.init();
      const rule = makeRule({
        id: 'rx-active',
        pattern: 'ignore.{0,10}instruction',
        type: RuleType.REGEX,
        status: RuleStatus.ACTIVE
      });
      await bank.addRule(rule);
      const results = bank.match('please ignore all instructions');
      const hit = results.find(r => r.ruleId === 'rx-active');
      expect(hit).toBeDefined();
      expect(hit!.matched).toBe(true);
    });

    it('matchShadow() 应匹配 SHADOW REGEX 规则', async () => {
      await bank.init();
      const rule = makeRule({
        id: 'rx-shadow',
        pattern: 'ignore.{0,10}instruction',
        type: RuleType.REGEX,
        status: RuleStatus.SHADOW
      });
      await bank.addRule(rule);
      const results = bank.matchShadow('please ignore all instructions');
      const hit = results.find(r => r.ruleId === 'rx-shadow');
      expect(hit).toBeDefined();
    });

    it('不匹配时不应出现在结果中', async () => {
      await bank.init();
      const rule = makeRule({
        id: 'rx-nomatch',
        pattern: 'very_specific_xyz_pattern_12345',
        type: RuleType.REGEX,
        status: RuleStatus.ACTIVE
      });
      await bank.addRule(rule);
      const results = bank.match('completely safe input text');
      expect(results.find(r => r.ruleId === 'rx-nomatch')).toBeUndefined();
    });
  });

  // --- 规则晋升 SHADOW → ACTIVE ---
  describe('规则晋升 (promoteShadowRules)', () => {
    it('命中≥3 且 fp_rate≤30% 的 SHADOW 规则应被晋升为 ACTIVE', async () => {
      await bank.init();
      const rule = makeRule({ id: 'promo-1', status: RuleStatus.SHADOW });
      await bank.addRule(rule);

      // 记录 3 次命中，0 次误报
      await bank.recordHit('promo-1', false);
      await bank.recordHit('promo-1', false);
      await bank.recordHit('promo-1', false);

      const promoted = await bank.promoteShadowRules(3, 0.3);
      expect(promoted).toBeGreaterThanOrEqual(1);
      expect(bank.getRule('promo-1')!.status).toBe(RuleStatus.ACTIVE);
    });

    it('命中不足 3 次的规则不应被晋升', async () => {
      await bank.init();
      const rule = makeRule({ id: 'promo-low', status: RuleStatus.SHADOW });
      await bank.addRule(rule);
      await bank.recordHit('promo-low', false);
      await bank.recordHit('promo-low', false);

      await bank.promoteShadowRules(3, 0.3);
      expect(bank.getRule('promo-low')!.status).toBe(RuleStatus.SHADOW);
    });

    it('fp_rate > 30% 的规则不应被晋升', async () => {
      await bank.init();
      const rule = makeRule({ id: 'promo-fp', status: RuleStatus.SHADOW });
      await bank.addRule(rule);
      // 3 hits, 2 FP → fp_rate ≈ 0.667 > 0.3
      await bank.recordHit('promo-fp', false);
      await bank.recordHit('promo-fp', true);
      await bank.recordHit('promo-fp', true);

      await bank.promoteShadowRules(3, 0.3);
      expect(bank.getRule('promo-fp')!.status).toBe(RuleStatus.SHADOW);
    });
  });

  // --- 规则废弃 (pruneIneffectiveRules) ---
  describe('规则废弃 (pruneIneffectiveRules)', () => {
    it('效果分数过低且命中足够的 ACTIVE 规则应被废弃', async () => {
      await bank.init();
      const now = Date.now();
      const rule: DefenseRule = {
        ...makeRule({ id: 'prune-1', status: RuleStatus.ACTIVE }),
        hitCount: 10,
        falsePositiveCount: 9,
        effectivenessScore: 0.05
      };
      await bank.addRule(rule);
      const pruned = await bank.pruneIneffectiveRules(0.2, 5);
      expect(pruned).toBeGreaterThanOrEqual(1);
      expect(bank.getRule('prune-1')!.status).toBe(RuleStatus.DEPRECATED);
    });

    it('命中次数不足的低效规则不应被废弃', async () => {
      await bank.init();
      const rule: DefenseRule = {
        ...makeRule({ id: 'prune-low-hits', status: RuleStatus.ACTIVE }),
        hitCount: 2,
        falsePositiveCount: 2,
        effectivenessScore: 0.0
      };
      await bank.addRule(rule);
      await bank.pruneIneffectiveRules(0.2, 5);
      expect(bank.getRule('prune-low-hits')!.status).toBe(RuleStatus.ACTIVE);
    });
  });

  // --- removeRule ---
  describe('removeRule()', () => {
    it('应从规则库中删除指定规则', async () => {
      await bank.init();
      const rule = makeRule({ id: 'del-1' });
      await bank.addRule(rule);
      expect(bank.getRule('del-1')).not.toBeNull();
      await bank.removeRule('del-1');
      expect(bank.getRule('del-1')).toBeNull();
    });
  });

  // --- getRuleCounts ---
  describe('getRuleCounts()', () => {
    it('应正确统计各状态规则数量', async () => {
      await bank.init();
      // Clear and add known rules
      const active = makeRule({ id: 'cnt-a', status: RuleStatus.ACTIVE });
      const shadow = makeRule({ id: 'cnt-s', status: RuleStatus.SHADOW });
      const deprecated = makeRule({ id: 'cnt-d', status: RuleStatus.DEPRECATED });
      await bank.addRule(active);
      await bank.addRule(shadow);
      await bank.addRule(deprecated);

      const counts = bank.getRuleCounts();
      expect(counts.active).toBeGreaterThanOrEqual(1);
      expect(counts.shadow).toBeGreaterThanOrEqual(1);
      expect(counts.deprecated).toBeGreaterThanOrEqual(1);
    });
  });

  // --- createRule ---
  describe('createRule()', () => {
    it('createRule() 应返回状态为 SHADOW 的新规则', async () => {
      await bank.init();
      const rule = bank.createRule(
        'Test',
        'desc',
        'pattern123',
        RuleType.KEYWORD,
        InjectionCategory.DATA_EXFILTRATION,
        'manual'
      );
      expect(rule.status).toBe(RuleStatus.SHADOW);
      expect(rule.id).toMatch(/^evo_/);
      expect(rule.hitCount).toBe(0);
    });
  });

  // --- 持久化与重新加载 ---
  describe('持久化与重新加载', () => {
    it('关闭后重新打开应恢复所有规则', async () => {
      await bank.init();
      const rule = makeRule({ id: 'persist-rule', pattern: 'persist_xyz_pattern' });
      await bank.addRule(rule);
      const countBefore = bank.getAllRules().length;

      const bank2 = new DefenseRuleBank(rulesPath);
      await bank2.init();
      expect(bank2.getAllRules().length).toBe(countBefore);
      expect(bank2.getRule('persist-rule')).not.toBeNull();
    });

    it('ACTIVE 规则在重新加载后应仍可匹配', async () => {
      await bank.init();
      const rule = makeRule({
        id: 'persist-active',
        pattern: 'load_test_keyword',
        type: RuleType.KEYWORD,
        status: RuleStatus.ACTIVE
      });
      await bank.addRule(rule);

      const bank2 = new DefenseRuleBank(rulesPath);
      await bank2.init();
      const results = bank2.match('this has load_test_keyword in it');
      expect(results.find(r => r.ruleId === 'persist-active')).toBeDefined();
    });
  });
});
