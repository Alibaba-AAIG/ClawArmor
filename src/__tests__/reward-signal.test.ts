/**
 * Unit tests for DefenseRewardSignal
 */

import { DefenseRewardSignal, DEFAULT_REWARD_CONFIG, RewardConfig } from '../evolve/reward-signal';
import { DefenseEvent, DefenseRule, RuleStatus, RuleType, RewardSignal } from '../evolve/types';
import { RiskLevel, InjectionCategory } from '../types';

// --- Helpers ---

function makeRule(overrides: Partial<DefenseRule> = {}): DefenseRule {
  const now = Date.now();
  return {
    id: 'rule-test',
    title: 'Test Rule',
    description: 'test',
    pattern: 'test',
    type: RuleType.KEYWORD,
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    status: RuleStatus.ACTIVE,
    createdAt: now,
    updatedAt: now,
    hitCount: 5,
    falsePositiveCount: 0,
    effectivenessScore: 0.8,
    source: 'manual',
    ...overrides
  };
}

function makeEvent(overrides: Partial<DefenseEvent> = {}): DefenseEvent {
  return {
    id: 'evt-test',
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

// --- Tests ---

describe('DefenseRewardSignal', () => {
  let signal: DefenseRewardSignal;
  const rule = makeRule();

  beforeEach(() => {
    signal = new DefenseRewardSignal();
  });

  // --- True Positive ---
  describe('True Positive (匹配 + 高风险输入)', () => {
    it('TP 高风险应返回正奖励', () => {
      const event = makeEvent({ riskLevel: RiskLevel.HIGH });
      const result = signal.computeRuleReward(rule, event, true);
      expect(result.reward).toBeGreaterThan(0);
      expect(result.context.truePositive).toBe(true);
      expect(result.context.falsePositive).toBe(false);
    });

    it('TP CRITICAL 应比 TP HIGH 奖励更高（严重度权重）', () => {
      const evtHigh = makeEvent({ riskLevel: RiskLevel.HIGH });
      const evtCritical = makeEvent({ riskLevel: RiskLevel.CRITICAL });
      const rHigh = signal.computeRuleReward(rule, evtHigh, true);
      const rCritical = signal.computeRuleReward(rule, evtCritical, true);
      expect(rCritical.reward).toBeGreaterThan(rHigh.reward);
    });

    it('TP 奖励应等于 truePositiveReward * severityWeight', () => {
      const event = makeEvent({ riskLevel: RiskLevel.CRITICAL });
      const result = signal.computeRuleReward(rule, event, true);
      const expected =
        DEFAULT_REWARD_CONFIG.truePositiveReward *
        DEFAULT_REWARD_CONFIG.severityWeights[RiskLevel.CRITICAL];
      expect(result.reward).toBeCloseTo(expected);
    });
  });

  // --- False Positive ---
  describe('False Positive (匹配 + 安全输入)', () => {
    it('FP 应返回负奖励', () => {
      const event = makeEvent({ riskLevel: RiskLevel.NONE });
      const result = signal.computeRuleReward(rule, event, true);
      expect(result.reward).toBeLessThan(0);
      expect(result.context.falsePositive).toBe(true);
      expect(result.context.truePositive).toBe(false);
    });

    it('FP 奖励应等于 falsePositivePenalty', () => {
      const event = makeEvent({ riskLevel: RiskLevel.NONE });
      const result = signal.computeRuleReward(rule, event, true);
      expect(result.reward).toBeCloseTo(DEFAULT_REWARD_CONFIG.falsePositivePenalty);
    });
  });

  // --- True Negative ---
  describe('True Negative (不匹配 + 安全输入)', () => {
    it('TN 应返回小正奖励', () => {
      const event = makeEvent({ riskLevel: RiskLevel.NONE });
      const result = signal.computeRuleReward(rule, event, false);
      expect(result.reward).toBeGreaterThanOrEqual(0);
      expect(result.reward).toBeCloseTo(DEFAULT_REWARD_CONFIG.trueNegativeReward);
    });

    it('TN context.truePositive 和 falsePositive 均为 false', () => {
      const event = makeEvent({ riskLevel: RiskLevel.NONE });
      const result = signal.computeRuleReward(rule, event, false);
      expect(result.context.truePositive).toBe(false);
      expect(result.context.falsePositive).toBe(false);
    });
  });

  // --- False Negative ---
  describe('False Negative (不匹配 + 高风险输入)', () => {
    it('FN 应返回负奖励', () => {
      const event = makeEvent({ riskLevel: RiskLevel.HIGH });
      const result = signal.computeRuleReward(rule, event, false);
      expect(result.reward).toBeLessThan(0);
    });

    it('FN CRITICAL 应比 FN HIGH 惩罚更重', () => {
      const evtHigh = makeEvent({ riskLevel: RiskLevel.HIGH });
      const evtCritical = makeEvent({ riskLevel: RiskLevel.CRITICAL });
      const rHigh = signal.computeRuleReward(rule, evtHigh, false);
      const rCritical = signal.computeRuleReward(rule, evtCritical, false);
      expect(rCritical.reward).toBeLessThan(rHigh.reward);
    });

    it('FN 奖励应等于 falseNegativePenalty * severityWeight', () => {
      const event = makeEvent({ riskLevel: RiskLevel.CRITICAL });
      const result = signal.computeRuleReward(rule, event, false);
      const expected =
        DEFAULT_REWARD_CONFIG.falseNegativePenalty *
        DEFAULT_REWARD_CONFIG.severityWeights[RiskLevel.CRITICAL];
      expect(result.reward).toBeCloseTo(expected);
    });
  });

  // --- normalizedReward ---
  describe('normalizedReward 范围', () => {
    const cases = [
      { riskLevel: RiskLevel.NONE, isMatch: true },
      { riskLevel: RiskLevel.NONE, isMatch: false },
      { riskLevel: RiskLevel.HIGH, isMatch: true },
      { riskLevel: RiskLevel.HIGH, isMatch: false },
      { riskLevel: RiskLevel.CRITICAL, isMatch: true },
      { riskLevel: RiskLevel.CRITICAL, isMatch: false }
    ];

    cases.forEach(({ riskLevel, isMatch }) => {
      it(`riskLevel=${riskLevel}, isMatch=${isMatch} → normalizedReward ∈ [-1, 1]`, () => {
        const event = makeEvent({ riskLevel });
        const result = signal.computeRuleReward(rule, event, isMatch);
        expect(result.normalizedReward).toBeGreaterThanOrEqual(-1);
        expect(result.normalizedReward).toBeLessThanOrEqual(1);
      });
    });
  });

  // --- 自定义配置 ---
  describe('自定义 RewardConfig', () => {
    it('应使用自定义奖励值', () => {
      const custom = new DefenseRewardSignal({ truePositiveReward: 2.0 });
      const event = makeEvent({ riskLevel: RiskLevel.CRITICAL });
      const result = custom.computeRuleReward(rule, event, true);
      const expected = 2.0 * DEFAULT_REWARD_CONFIG.severityWeights[RiskLevel.CRITICAL];
      expect(result.reward).toBeCloseTo(expected);
    });
  });

  // --- computeGroupNormalizedRewards (GRPO) ---
  describe('computeGroupNormalizedRewards (GRPO 风格)', () => {
    it('空数组应返回空数组', () => {
      expect(signal.computeGroupNormalizedRewards([])).toEqual([]);
    });

    it('单元素应返回 normalizedReward=0', () => {
      const r: RewardSignal = {
        ruleId: 'r1',
        reward: 1.0,
        normalizedReward: 0.5,
        context: { truePositive: true, falsePositive: false, severity: RiskLevel.HIGH }
      };
      const result = signal.computeGroupNormalizedRewards([r]);
      expect(result[0].normalizedReward).toBe(0);
    });

    it('多元素应进行归一化 (mean=0, std=1 后)', () => {
      const rewards: RewardSignal[] = [
        { ruleId: 'r1', reward: 1.0, normalizedReward: 0, context: { truePositive: true, falsePositive: false, severity: RiskLevel.HIGH } },
        { ruleId: 'r2', reward: -1.0, normalizedReward: 0, context: { truePositive: false, falsePositive: true, severity: RiskLevel.NONE } },
        { ruleId: 'r3', reward: 0.0, normalizedReward: 0, context: { truePositive: false, falsePositive: false, severity: RiskLevel.NONE } }
      ];
      const normalized = signal.computeGroupNormalizedRewards(rewards);
      // Mean should be ~0, std ~0.816
      const mean = normalized.reduce((a, r) => a + r.normalizedReward, 0) / normalized.length;
      expect(mean).toBeCloseTo(0, 5);
    });

    it('归一化后高奖励的 normalizedReward 应高于低奖励', () => {
      const rewards: RewardSignal[] = [
        { ruleId: 'r1', reward: 1.0, normalizedReward: 0, context: { truePositive: true, falsePositive: false, severity: RiskLevel.HIGH } },
        { ruleId: 'r2', reward: -0.5, normalizedReward: 0, context: { truePositive: false, falsePositive: true, severity: RiskLevel.NONE } }
      ];
      const normalized = signal.computeGroupNormalizedRewards(rewards);
      const n1 = normalized.find(r => r.ruleId === 'r1')!.normalizedReward;
      const n2 = normalized.find(r => r.ruleId === 'r2')!.normalizedReward;
      expect(n1).toBeGreaterThan(n2);
    });
  });

  // --- aggregateRuleRewards ---
  describe('aggregateRuleRewards()', () => {
    it('空数组应返回零值聚合', () => {
      const agg = signal.aggregateRuleRewards([]);
      expect(agg.totalReward).toBe(0);
      expect(agg.avgReward).toBe(0);
    });

    it('应正确计算 totalReward 和 avgReward', () => {
      const signals: RewardSignal[] = [
        { ruleId: 'r', reward: 0.8, normalizedReward: 0.4, context: { truePositive: true, falsePositive: false, severity: RiskLevel.HIGH } },
        { ruleId: 'r', reward: -0.5, normalizedReward: -0.25, context: { truePositive: false, falsePositive: true, severity: RiskLevel.NONE } },
        { ruleId: 'r', reward: 0.1, normalizedReward: 0.05, context: { truePositive: false, falsePositive: false, severity: RiskLevel.NONE } }
      ];
      const agg = signal.aggregateRuleRewards(signals);
      expect(agg.totalReward).toBeCloseTo(0.4);
      expect(agg.avgReward).toBeCloseTo(0.4 / 3);
      expect(agg.truePositives).toBe(1);
      expect(agg.falsePositives).toBe(1);
    });
  });

  // --- computeJointReward ---
  describe('computeJointReward()', () => {
    it('应返回 ruleRewards 和 sessionReward', () => {
      const rule1 = makeRule({ id: 'r1' });
      const e1 = makeEvent({ riskLevel: RiskLevel.HIGH, blocked: true });
      const ruleReward = signal.computeRuleReward(rule1, e1, true);
      const sessionEvents = [e1];

      const { ruleRewards, sessionReward } = signal.computeJointReward([ruleReward], sessionEvents);
      expect(ruleRewards.length).toBe(1);
      expect(typeof sessionReward).toBe('number');
    });
  });
});
