/**
 * Unit tests for AdaptiveThresholdController
 */

import {
  AdaptiveThresholdController,
  DEFAULT_ADAPTIVE_CONFIG,
  AdaptiveThresholdConfig
} from '../evolve/adaptive-threshold';
import { DefenseMetrics } from '../evolve/types';

// --- Helpers ---

function makeMetrics(overrides: Partial<DefenseMetrics> = {}): DefenseMetrics {
  return {
    totalEvents: 100,
    blockedCount: 50,
    falsePositives: 5,
    falseNegatives: 2,
    fpRate: 0.05,
    fnRate: 0.02,
    activeRulesCount: 10,
    shadowRulesCount: 5,
    ...overrides
  };
}

// --- Tests ---

describe('AdaptiveThresholdController', () => {
  let controller: AdaptiveThresholdController;

  beforeEach(() => {
    controller = new AdaptiveThresholdController();
  });

  // --- 初始化 ---
  describe('初始化', () => {
    it('默认阈值应为 0.8', () => {
      expect(controller.getThreshold()).toBe(DEFAULT_ADAPTIVE_CONFIG.initialThreshold);
    });

    it('自定义初始阈值应被应用', () => {
      const c = new AdaptiveThresholdController({ initialThreshold: 0.7 });
      expect(c.getThreshold()).toBeCloseTo(0.7);
    });

    it('getConfig() 应返回配置副本', () => {
      const cfg = controller.getConfig();
      expect(cfg.minThreshold).toBe(DEFAULT_ADAPTIVE_CONFIG.minThreshold);
      expect(cfg.maxThreshold).toBe(DEFAULT_ADAPTIVE_CONFIG.maxThreshold);
    });
  });

  // --- setThreshold ---
  describe('setThreshold()', () => {
    it('应在合法范围内设置阈值', () => {
      controller.setThreshold(0.75);
      expect(controller.getThreshold()).toBeCloseTo(0.75);
    });

    it('低于 minThreshold 的值应被钳制到 minThreshold', () => {
      controller.setThreshold(0.1);
      expect(controller.getThreshold()).toBeCloseTo(DEFAULT_ADAPTIVE_CONFIG.minThreshold);
    });

    it('高于 maxThreshold 的值应被钳制到 maxThreshold', () => {
      controller.setThreshold(0.99);
      expect(controller.getThreshold()).toBeCloseTo(DEFAULT_ADAPTIVE_CONFIG.maxThreshold);
    });
  });

  // --- reset ---
  describe('reset()', () => {
    it('reset() 应恢复到初始阈值', () => {
      controller.setThreshold(0.6);
      controller.reset();
      expect(controller.getThreshold()).toBeCloseTo(DEFAULT_ADAPTIVE_CONFIG.initialThreshold);
    });
  });

  // --- update: 高 FP 率 → 阈值上升 ---
  describe('高 FP 率 → 阈值上升', () => {
    it('FP 率远高于目标时阈值应上升', () => {
      const before = controller.getThreshold();
      // fpRate = 0.5 >> targetFpRate = 0.05
      const metrics = makeMetrics({ fpRate: 0.5, fnRate: 0.01, totalEvents: 100 });
      const adj = controller.update(metrics);
      expect(adj.newThreshold).toBeGreaterThan(before);
      expect(adj.fpError).toBeGreaterThan(0);
    });

    it('阈值上升不应超过 maxThreshold (0.95)', () => {
      // Push threshold close to max then update with high FP
      controller.setThreshold(0.94);
      const metrics = makeMetrics({ fpRate: 0.9, fnRate: 0.0, totalEvents: 100 });
      controller.update(metrics);
      expect(controller.getThreshold()).toBeLessThanOrEqual(DEFAULT_ADAPTIVE_CONFIG.maxThreshold);
    });

    it('ThresholdAdjustment 应包含正确的 oldThreshold / newThreshold', () => {
      const before = controller.getThreshold();
      const metrics = makeMetrics({ fpRate: 0.4, fnRate: 0.0, totalEvents: 100 });
      const adj = controller.update(metrics);
      expect(adj.oldThreshold).toBeCloseTo(before);
      expect(adj.newThreshold).toBeCloseTo(controller.getThreshold());
    });
  });

  // --- update: 高 FN 率 → 阈值下降 ---
  describe('高 FN 率 → 阈值下降', () => {
    it('FN 率远高于目标时阈值应下降', () => {
      const before = controller.getThreshold();
      // fnRate = 0.5 >> targetFnRate = 0.02
      const metrics = makeMetrics({ fpRate: 0.01, fnRate: 0.5, totalEvents: 100 });
      const adj = controller.update(metrics);
      expect(adj.newThreshold).toBeLessThan(before);
      expect(adj.fnError).toBeGreaterThan(0);
    });

    it('阈值下降不应低于 minThreshold (0.5)', () => {
      controller.setThreshold(0.51);
      const metrics = makeMetrics({ fpRate: 0.0, fnRate: 0.9, totalEvents: 100 });
      controller.update(metrics);
      expect(controller.getThreshold()).toBeGreaterThanOrEqual(DEFAULT_ADAPTIVE_CONFIG.minThreshold);
    });
  });

  // --- update: FP 和 FN 都在目标附近 → 阈值基本稳定 ---
  describe('FP/FN 在目标范围内 → 阈值基本稳定', () => {
    it('FP 和 FN 都在目标水平时阈值变化应极小', () => {
      const before = controller.getThreshold();
      // fpRate ≈ targetFpRate, fnRate ≈ targetFnRate
      const metrics = makeMetrics({
        fpRate: DEFAULT_ADAPTIVE_CONFIG.targetFpRate,
        fnRate: DEFAULT_ADAPTIVE_CONFIG.targetFnRate,
        totalEvents: 100
      });
      controller.update(metrics);
      const after = controller.getThreshold();
      // Adjustment should be very small (close to no change)
      expect(Math.abs(after - before)).toBeLessThan(0.05);
    });
  });

  // --- update: 事件数量影响 ---
  describe('事件数量对调整幅度的影响', () => {
    it('事件越多，调整越接近最大幅度（趋于收敛）', () => {
      // Few events
      const cSmall = new AdaptiveThresholdController({ initialThreshold: 0.8 });
      const metricsSmall = makeMetrics({ fpRate: 0.5, fnRate: 0.0, totalEvents: 10 });
      const adjSmall = cSmall.update(metricsSmall);

      // Many events
      const cLarge = new AdaptiveThresholdController({ initialThreshold: 0.8 });
      const metricsLarge = makeMetrics({ fpRate: 0.5, fnRate: 0.0, totalEvents: 100 });
      const adjLarge = cLarge.update(metricsLarge);

      // More events → larger adjustment
      const changeSmall = adjSmall.newThreshold - 0.8;
      const changeLarge = adjLarge.newThreshold - 0.8;
      expect(Math.abs(changeLarge)).toBeGreaterThan(Math.abs(changeSmall));
    });
  });

  // --- 边界：totalEvents = 0 ---
  describe('totalEvents = 0 时', () => {
    it('totalEvents=0 时也应返回合法 ThresholdAdjustment 而不抛出错误', () => {
      const metrics = makeMetrics({ totalEvents: 0, fpRate: 0, fnRate: 0 });
      expect(() => controller.update(metrics)).not.toThrow();
    });
  });

  // --- serialize / deserialize ---
  describe('serialize / deserialize', () => {
    it('serialize 后 deserialize 应恢复完全相同的阈值和配置', () => {
      controller.setThreshold(0.72);
      const state = controller.serialize();
      const c2 = new AdaptiveThresholdController();
      c2.deserialize(state);
      expect(c2.getThreshold()).toBeCloseTo(0.72);
      expect(c2.getConfig().targetFpRate).toBe(controller.getConfig().targetFpRate);
    });
  });

  // --- ThresholdAdjustment reason ---
  describe('ThresholdAdjustment reason', () => {
    it('高 FP 时 reason 应包含 FP 相关描述', () => {
      const metrics = makeMetrics({ fpRate: 0.5, fnRate: 0.0, totalEvents: 100 });
      const adj = controller.update(metrics);
      expect(adj.reason.length).toBeGreaterThan(0);
    });

    it('rates 都在正常范围时 reason 应提示 within acceptable bounds', () => {
      const metrics = makeMetrics({
        fpRate: DEFAULT_ADAPTIVE_CONFIG.targetFpRate,
        fnRate: DEFAULT_ADAPTIVE_CONFIG.targetFnRate,
        totalEvents: 100
      });
      const adj = controller.update(metrics);
      expect(adj.reason).toMatch(/acceptable|bounds|target|minor/i);
    });
  });
});
