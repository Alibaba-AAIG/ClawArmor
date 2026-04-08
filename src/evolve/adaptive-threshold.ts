/**
 * Adaptive Threshold Controller
 * Proportional controller for adjusting risk thresholds based on FP/FN rates
 * Inspired by AdaptiveKLController from SkillRL
 * Ported from ClawArmor Python implementation
 */

import { DefenseMetrics, ThresholdAdjustment } from './types';
import { logger } from '../utils';

export interface AdaptiveThresholdConfig {
  initialThreshold: number;
  targetFpRate: number;
  targetFnRate: number;
  horizon: number;        // Horizon for adjustment calculation
  fpWeight: number;       // Weight for false positive error
  fnWeight: number;       // Weight for false negative error
  minThreshold: number;   // Minimum allowed threshold
  maxThreshold: number;   // Maximum allowed threshold
}

export const DEFAULT_ADAPTIVE_CONFIG: AdaptiveThresholdConfig = {
  initialThreshold: 0.8,
  targetFpRate: 0.05,
  targetFnRate: 0.02,
  horizon: 100,
  fpWeight: 0.6,
  fnWeight: 0.4,
  minThreshold: 0.5,
  maxThreshold: 0.95
};

export class AdaptiveThresholdController {
  private threshold: number;
  private config: AdaptiveThresholdConfig;

  constructor(config: Partial<AdaptiveThresholdConfig> = {}) {
    this.config = { ...DEFAULT_ADAPTIVE_CONFIG, ...config };
    this.threshold = this.config.initialThreshold;
  }

  /**
   * Get current threshold
   */
  getThreshold(): number {
    return this.threshold;
  }

  /**
   * Set threshold directly (for initialization)
   */
  setThreshold(threshold: number): void {
    this.threshold = Math.max(
      this.config.minThreshold,
      Math.min(this.config.maxThreshold, threshold)
    );
  }

  /**
   * Update threshold based on defense metrics
   * 
   * Algorithm (from SkillRL's AdaptiveKLController):
   * 1. Calculate FP error: clip(actual_fp / target_fp - 1, -0.2, 0.2)
   * 2. Calculate FN error: clip(actual_fn / target_fn - 1, -0.2, 0.2)
   * 3. Adjust threshold: threshold *= (1 + (fp_error * fp_weight - fn_error * fn_weight) * n_events / horizon)
   * 
   * Rationale:
   * - High FP rate → Increase threshold (be less sensitive)
   * - High FN rate → Decrease threshold (be more sensitive)
   */
  update(metrics: DefenseMetrics): ThresholdAdjustment {
    const { fpRate, fnRate, totalEvents } = metrics;
    const { targetFpRate, targetFnRate, horizon, fpWeight, fnWeight } = this.config;

    // Calculate errors (clipped to prevent extreme adjustments)
    const fpError = this.clip(fpRate / targetFpRate - 1, -0.2, 0.2);
    const fnError = this.clip(fnRate / targetFnRate - 1, -0.2, 0.2);

    // Calculate adjustment factor
    // Note: FP error increases threshold, FN error decreases threshold
    const adjustmentFactor = 1 + (fpError * fpWeight - fnError * fnWeight) * Math.min(totalEvents, horizon) / horizon;

    const oldThreshold = this.threshold;
    let newThreshold = oldThreshold * adjustmentFactor;

    // Clamp to valid range
    newThreshold = Math.max(this.config.minThreshold, Math.min(this.config.maxThreshold, newThreshold));

    this.threshold = newThreshold;

    const adjustment: ThresholdAdjustment = {
      oldThreshold,
      newThreshold,
      fpError,
      fnError,
      reason: this.generateReason(fpError, fnError, fpRate, fnRate)
    };

    logger.info(`[AdaptiveThreshold] threshold adjusted ${oldThreshold.toFixed(4)} -> ${newThreshold.toFixed(4)} (fp_error=${fpError.toFixed(3)}, fn_error=${fnError.toFixed(3)})`);

    return adjustment;
  }

  /**
   * Clip value to range [min, max]
   */
  private clip(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, value));
  }

  /**
   * Generate human-readable reason for adjustment
   */
  private generateReason(fpError: number, fnError: number, fpRate: number, fnRate: number): string {
    const reasons: string[] = [];

    if (fpError > 0.05) {
      reasons.push(`FP rate ${(fpRate * 100).toFixed(1)}% above target ${(this.config.targetFpRate * 100).toFixed(1)}%`);
    } else if (fpError < -0.05) {
      reasons.push(`FP rate ${(fpRate * 100).toFixed(1)}% below target`);
    }

    if (fnError > 0.05) {
      reasons.push(`FN rate ${(fnRate * 100).toFixed(1)}% above target ${(this.config.targetFnRate * 100).toFixed(1)}%`);
    } else if (fnError < -0.05) {
      reasons.push(`FN rate ${(fnRate * 100).toFixed(1)}% below target`);
    }

    if (reasons.length === 0) {
      return 'Rates within acceptable bounds, minor adjustment';
    }

    return reasons.join('; ');
  }

  /**
   * Reset to initial threshold
   */
  reset(): void {
    this.threshold = this.config.initialThreshold;
    logger.info(`[AdaptiveThreshold] Reset to initial threshold ${this.threshold}`);
  }

  /**
   * Get configuration
   */
  getConfig(): AdaptiveThresholdConfig {
    return { ...this.config };
  }

  /**
   * Serialize state for persistence
   */
  serialize(): { threshold: number; config: AdaptiveThresholdConfig } {
    return {
      threshold: this.threshold,
      config: this.config
    };
  }

  /**
   * Deserialize state from persistence
   */
  deserialize(state: { threshold: number; config: AdaptiveThresholdConfig }): void {
    this.threshold = state.threshold;
    this.config = { ...DEFAULT_ADAPTIVE_CONFIG, ...state.config };
  }
}