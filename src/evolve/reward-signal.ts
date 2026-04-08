/**
 * Defense Reward Signal
 * Multi-granularity reward signals inspired by GRPO/GiGPO
 * Ported from ClawArmor Python implementation
 */

import { DefenseEvent, DefenseRule, RewardSignal } from './types';
import { RiskLevel } from '../types';
import { logger } from '../utils';

export interface RewardConfig {
  truePositiveReward: number;
  falsePositivePenalty: number;
  falseNegativePenalty: number;
  trueNegativeReward: number;
  severityWeights: Record<RiskLevel, number>;
}

export const DEFAULT_REWARD_CONFIG: RewardConfig = {
  truePositiveReward: 1.0,
  falsePositivePenalty: -0.5,
  falseNegativePenalty: -1.0,
  trueNegativeReward: 0.1,
  severityWeights: {
    [RiskLevel.NONE]: 0.1,
    [RiskLevel.LOW]: 0.3,
    [RiskLevel.MEDIUM]: 0.5,
    [RiskLevel.HIGH]: 0.8,
    [RiskLevel.CRITICAL]: 1.0
  }
};

export class DefenseRewardSignal {
  private config: RewardConfig;

  constructor(config: Partial<RewardConfig> = {}) {
    this.config = { ...DEFAULT_REWARD_CONFIG, ...config };
  }

  /**
   * Compute reward for a single rule based on detection outcome
   * 
   * Reward structure:
   * - True Positive: +1.0 * severity_weight (correctly detected attack)
   * - False Positive: -0.5 (incorrectly flagged safe input)
   * - True Negative: +0.1 (correctly passed safe input)
   * - False Negative: -1.0 * severity_weight (missed attack)
   */
  computeRuleReward(
    rule: DefenseRule,
    event: DefenseEvent,
    isMatch: boolean
  ): RewardSignal {
    let reward: number;
    let truePositive = false;
    let falsePositive = false;

    if (isMatch) {
      // Rule matched the input
      if (event.riskLevel !== RiskLevel.NONE) {
        // True positive: matched and input was actually risky
        reward = this.config.truePositiveReward * this.config.severityWeights[event.riskLevel];
        truePositive = true;
      } else {
        // False positive: matched but input was safe
        reward = this.config.falsePositivePenalty;
        falsePositive = true;
      }
    } else {
      // Rule did not match
      if (event.riskLevel !== RiskLevel.NONE) {
        // False negative: didn't match but input was risky
        reward = this.config.falseNegativePenalty * this.config.severityWeights[event.riskLevel];
      } else {
        // True negative: didn't match and input was safe
        reward = this.config.trueNegativeReward;
      }
    }

    return {
      ruleId: rule.id,
      reward,
      normalizedReward: this.normalizeReward(reward),
      context: {
        truePositive,
        falsePositive,
        severity: event.riskLevel
      }
    };
  }

  /**
   * Compute joint reward for rule-level + session-level
   * Inspired by GiGPO's joint advantage estimation
   */
  computeJointReward(
    ruleRewards: RewardSignal[],
    sessionEvents: DefenseEvent[]
  ): { ruleRewards: RewardSignal[]; sessionReward: number } {
    // Calculate session-level reward
    const sessionStats = this.analyzeSession(sessionEvents);
    const sessionReward = this.computeSessionReward(sessionStats);

    // Combine with rule-level rewards
    const combinedRewards = ruleRewards.map(rr => ({
      ...rr,
      reward: rr.reward + sessionReward * 0.3, // 30% weight for session context
      normalizedReward: this.normalizeReward(rr.reward + sessionReward * 0.3)
    }));

    return {
      ruleRewards: combinedRewards,
      sessionReward
    };
  }

  /**
   * Analyze session statistics
   */
  private analyzeSession(events: DefenseEvent[]): {
    totalEvents: number;
    blockedCount: number;
    fpCount: number;
    fnCount: number;
    highRiskCount: number;
  } {
    return {
      totalEvents: events.length,
      blockedCount: events.filter(e => e.blocked).length,
      fpCount: events.filter(e => e.falsePositive).length,
      fnCount: events.filter(e => e.missedAttack).length,
      highRiskCount: events.filter(e => 
        e.riskLevel === RiskLevel.HIGH || e.riskLevel === RiskLevel.CRITICAL
      ).length
    };
  }

  /**
   * Compute session-level reward
   */
  private computeSessionReward(stats: {
    totalEvents: number;
    blockedCount: number;
    fpCount: number;
    fnCount: number;
    highRiskCount: number;
  }): number {
    if (stats.totalEvents === 0) return 0;

    const fpRate = stats.fpCount / stats.totalEvents;
    const fnRate = stats.fnCount / stats.totalEvents;
    const blockRate = stats.blockedCount / stats.totalEvents;
    const highRiskRate = stats.highRiskCount / stats.totalEvents;

    // Session reward components:
    // - High block rate on high-risk inputs: positive
    // - Low FP rate: positive
    // - Low FN rate: positive
    const reward = (
      (blockRate * highRiskRate * 0.4) +
      ((1 - fpRate) * 0.3) +
      ((1 - fnRate) * 0.3)
    );

    return reward;
  }

  /**
   * Normalize reward to [-1, 1] range
   */
  private normalizeReward(reward: number): number {
    // Clip to [-2, 2] then normalize to [-1, 1]
    const clipped = Math.max(-2, Math.min(2, reward));
    return clipped / 2;
  }

  /**
   * Compute group-normalized rewards (GRPO style)
   * 
   * GRPO: Group Relative Policy Optimization
   * - Compute mean and std of rewards in a group
     * - Normalize: (reward - mean) / std
   */
  computeGroupNormalizedRewards(rewards: RewardSignal[]): RewardSignal[] {
    if (rewards.length === 0) return [];
    if (rewards.length === 1) {
      return [{ ...rewards[0], normalizedReward: 0 }];
    }

    const values = rewards.map(r => r.reward);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    const std = Math.sqrt(variance) || 1; // Avoid division by zero

    return rewards.map(r => ({
      ...r,
      normalizedReward: (r.reward - mean) / std
    }));
  }

  /**
   * Aggregate rewards for a rule across multiple events
   */
  aggregateRuleRewards(signals: RewardSignal[]): {
    ruleId: string;
    totalReward: number;
    avgReward: number;
    normalizedReward: number;
    truePositives: number;
    falsePositives: number;
  } {
    if (signals.length === 0) {
      return {
        ruleId: '',
        totalReward: 0,
        avgReward: 0,
        normalizedReward: 0,
        truePositives: 0,
        falsePositives: 0
      };
    }

    const ruleId = signals[0].ruleId;
    const totalReward = signals.reduce((sum, s) => sum + s.reward, 0);
    const avgReward = totalReward / signals.length;
    const normalizedReward = signals.reduce((sum, s) => sum + s.normalizedReward, 0) / signals.length;
    const truePositives = signals.filter(s => s.context.truePositive).length;
    const falsePositives = signals.filter(s => s.context.falsePositive).length;

    return {
      ruleId,
      totalReward,
      avgReward,
      normalizedReward,
      truePositives,
      falsePositives
    };
  }

  /**
   * Get reward statistics for logging
   */
  getRewardStats(signals: RewardSignal[]): {
    count: number;
    mean: number;
    min: number;
    max: number;
    truePositives: number;
    falsePositives: number;
  } {
    if (signals.length === 0) {
      return { count: 0, mean: 0, min: 0, max: 0, truePositives: 0, falsePositives: 0 };
    }

    const rewards = signals.map(s => s.reward);
    return {
      count: signals.length,
      mean: rewards.reduce((a, b) => a + b, 0) / rewards.length,
      min: Math.min(...rewards),
      max: Math.max(...rewards),
      truePositives: signals.filter(s => s.context.truePositive).length,
      falsePositives: signals.filter(s => s.context.falsePositive).length
    };
  }

  /**
   * Log reward summary
   */
  logRewardSummary(signals: RewardSignal[], context: string): void {
    const stats = this.getRewardStats(signals);
    logger.info(`[RewardSignal] ${context}: count=${stats.count}, mean=${stats.mean.toFixed(3)}, ` +
      `min=${stats.min.toFixed(3)}, max=${stats.max.toFixed(3)}, ` +
      `TP=${stats.truePositives}, FP=${stats.falsePositives}`);
  }
}