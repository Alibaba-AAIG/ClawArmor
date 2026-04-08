/**
 * Evolve Manager
 * Orchestrates the adaptive defense evolution cycle
 * Ported from ClawArmor Python implementation
 */

import { DefenseEventStore } from './event-store';
import { DefenseRuleBank } from './rule-bank';
import { AdaptiveThresholdController } from './adaptive-threshold';
import { DefenseRewardSignal } from './reward-signal';
import { DefenseRuleUpdater } from './rule-updater';
import { 
  EvolveConfig, 
  DEFAULT_EVOLVE_CONFIG, 
  DefenseEvent, 
  DefenseRule,
  RuleMatchResult,
  EvolutionResult,
  RuleStatus,
  RuleType
} from './types';
import { RiskLevel } from '../types';
import { logger } from '../utils';
import * as fs from 'fs';
import * as path from 'path';

export class EvolveManager {
  private config: EvolveConfig;
  private eventStore: DefenseEventStore;
  private ruleBank: DefenseRuleBank;
  private thresholdController: AdaptiveThresholdController;
  private rewardSignal: DefenseRewardSignal;
  private ruleUpdater: DefenseRuleUpdater;
  private initialized: boolean = false;
  private isEvolving: boolean = false;

  constructor(config: Partial<EvolveConfig> = {}) {
    this.config = { ...DEFAULT_EVOLVE_CONFIG, ...config };
    
    this.eventStore = new DefenseEventStore(this.config.dbPath);
    this.ruleBank = new DefenseRuleBank(this.config.rulesPath);
    this.thresholdController = new AdaptiveThresholdController({
      targetFpRate: this.config.targetFpRate,
      targetFnRate: this.config.targetFnRate
    });
    this.rewardSignal = new DefenseRewardSignal();
    this.ruleUpdater = new DefenseRuleUpdater({
      llmApiBase: this.config.llmApiBase,
      llmApiKey: this.config.llmApiKey,
      llmModel: this.config.llmModel,
      maxRulesPerCycle: 3,
      temperature: 0.7
    });
  }

  /**
   * Initialize all components
   */
  async init(): Promise<void> {
    if (this.initialized) return;

    await Promise.all([
      this.eventStore.init(),
      this.ruleBank.init()
    ]);

    this.initialized = true;
    logger.info(`[EvolveManager] Initialized successfully`);
    logger.info(`[EvolveManager] LLM config: apiBase=${this.config.llmApiBase ? 'SET' : 'NOT SET'}, apiKey=${this.config.llmApiKey ? 'SET(' + this.config.llmApiKey.substring(0, 8) + '...)' : 'NOT SET'}, model=${this.config.llmModel}`);
  }

  /**
   * Check if evolve is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Get dynamic rules matching the input
   * Called by hooks to check for evolved rule matches
   */
  getDynamicRules(input: string): { active: RuleMatchResult[]; shadow: RuleMatchResult[] } {
    if (!this.initialized || !this.config.enabled) {
      return { active: [], shadow: [] };
    }

    const active = this.ruleBank.match(input);
    const shadow = this.ruleBank.matchShadow(input);

    return { active, shadow };
  }

  /**
   * Record a detection event and potentially trigger evolution
   */
  async onDetection(event: DefenseEvent): Promise<void> {
    if (!this.initialized || !this.config.enabled) return;

    // Record the event
    await this.eventStore.record(event);

    // Update rule hit counts for matched rules
    for (const ruleId of event.evolvedRulesMatched || []) {
      const isFalsePositive = event.riskLevel === RiskLevel.NONE;
      await this.ruleBank.recordHit(ruleId, isFalsePositive);
    }

    // Check if we should trigger evolution
    const currentCount = await this.eventStore.count();
    const lastTriggered = await this.eventStore.getLastTriggeredCount();
    const eventsSinceLast = currentCount - lastTriggered;

    if (eventsSinceLast >= this.config.updateInterval) {
      await this.eventStore.setLastTriggeredCount(currentCount);
      this.triggerEvolutionAsync();
    }
  }

  /**
   * Trigger evolution cycle asynchronously
   */
  private triggerEvolutionAsync(): void {
    if (this.isEvolving) {
      logger.info('[EvolveManager] Evolution already in progress, skipping');
      return;
    }

    // Run evolution in background
    setTimeout(() => this.runEvolution(), 0);
  }

  /**
   * Run a complete evolution cycle
   */
  private async runEvolution(): Promise<EvolutionResult | null> {
    if (this.isEvolving) return null;
    this.isEvolving = true;

    const cycleId = `evo_${Date.now()}`;
    logger.warn(`[EvolveManager] >>> evolution cycle started: ${cycleId}`);

    try {
      // 1. Compute metrics
      const metrics = await this.eventStore.getMetrics();
      const ruleCounts = this.ruleBank.getRuleCounts();
      metrics.activeRulesCount = ruleCounts.active;
      metrics.shadowRulesCount = ruleCounts.shadow;

      logger.info(`[EvolveManager] metrics: events=${metrics.totalEvents}, blocked=${metrics.blockedCount}, ` +
        `FP=${metrics.falsePositives}, FN=${metrics.falseNegatives}, ` +
        `active_rules=${metrics.activeRulesCount}, shadow_rules=${metrics.shadowRulesCount}`);

      // 2. Update threshold
      const thresholdAdjustment = this.thresholdController.update(metrics);
      
      // Persist threshold to file for Dashboard
      this.persistThreshold();

      // 3. Promote shadow rules
      const promoted = await this.ruleBank.promoteShadowRules(
        this.config.minHitsToPromote,
        this.config.maxFpRateToPromote
      );
      if (promoted > 0) {
        logger.warn(`[EvolveManager] Promoted ${promoted} shadow rules to ACTIVE!`);
      }

      // 4. Auto-label missed attacks
      const autoLabeledCount = await this.autoLabelMissedAttacks();
      if (autoLabeledCount > 0) {
        logger.info(`[EvolveManager] Auto-labeled ${autoLabeledCount} missed attacks`);
      }

      // 5. Analyze missed attacks and generate new rules
      const missedAttacks = await this.eventStore.getMissedAttacks();
      const newRules = await this.ruleUpdater.analyzeMissedAttacks(missedAttacks);
      if (newRules.length > 0) {
        await this.ruleBank.addRules(newRules);
        logger.warn(`[EvolveManager] Added ${newRules.length} new rules from missed attacks`);
      }

      // 6. Analyze false positives
      const falsePositives = await this.eventStore.getFalsePositives();
      const fpAnalysis = await this.ruleUpdater.analyzeFalsePositives(falsePositives);
      
      // Deprecate rules with high FP rate
      for (const ruleId of fpAnalysis.rulesToDeprecate) {
        await this.ruleBank.updateRuleStatus(ruleId, RuleStatus.DEPRECATED);
        logger.info(`[EvolveManager] Deprecated rule ${ruleId} due to high FP rate`);
      }

      // 7. Prune ineffective rules
      const pruned = await this.ruleBank.pruneIneffectiveRules(
        this.config.pruneThreshold,
        5 // minHits
      );
      if (pruned > 0) {
        logger.info(`[EvolveManager] Pruned ${pruned} ineffective rules`);
      }

      const result: EvolutionResult = {
        cycleId,
        timestamp: Date.now(),
        metrics,
        thresholdAdjustment,
        promotedRules: promoted > 0 ? [`${promoted} rules`] : [],
        newRules,
        prunedRules: pruned > 0 ? [`${pruned} rules`] : [],
        autoLabeledEvents: autoLabeledCount
      };

      logger.warn(`[EvolveManager] <<< evolution cycle completed: ${cycleId}`);
      return result;
    } catch (err) {
      logger.error(`[EvolveManager] Evolution cycle failed: ${err}`);
      return null;
    } finally {
      this.isEvolving = false;
    }
  }

  /**
   * Auto-label events that were marked as safe but might be attacks
   * Uses full trajectory for more accurate detection
   */
  private async autoLabelMissedAttacks(): Promise<number> {
    // Get recent events that were marked as safe (NONE risk)
    const recentEvents = await this.eventStore.getRecent(50);
    const safeEvents = recentEvents.filter(e => 
      e.riskLevel === RiskLevel.NONE && 
      !e.missedAttack && 
      !e.falsePositive
    );

    let labeledCount = 0;

    for (const event of safeEvents) {
      // Try LLM judge first with trajectory, fallback to heuristic
      let judgment;
      if (this.config.llmApiKey) {
        try {
          judgment = await this.ruleUpdater.llmJudgeRisk(event.input, event.trajectory);
        } catch {
          judgment = this.ruleUpdater.heuristicJudge(event.input, event.trajectory);
        }
      } else {
        judgment = this.ruleUpdater.heuristicJudge(event.input, event.trajectory);
      }

      if (judgment.isAttack && judgment.confidence > 0.6) {
        await this.eventStore.markMissedAttack([event.id]);
        labeledCount++;
        logger.info(`[EvolveManager] Auto-labeled missed attack: ${event.id}, source=${judgment.category}`);
      }
    }

    return labeledCount;
  }

  /**
   * Get current defense stats
   */
  async getStats(): Promise<{
    events: number;
    activeRules: number;
    shadowRules: number;
    threshold: number;
    isEvolving: boolean;
  }> {
    if (!this.initialized) {
      return { events: 0, activeRules: 0, shadowRules: 0, threshold: 0.8, isEvolving: false };
    }

    const counts = await this.eventStore.count();
    const ruleCounts = this.ruleBank.getRuleCounts();

    return {
      events: counts,
      activeRules: ruleCounts.active,
      shadowRules: ruleCounts.shadow,
      threshold: this.thresholdController.getThreshold(),
      isEvolving: this.isEvolving
    };
  }

  /**
   * Get all active rules
   */
  getActiveRules() {
    return this.ruleBank.getActiveRules();
  }

  /**
   * Get all shadow rules
   */
  getShadowRules() {
    return this.ruleBank.getShadowRules();
  }

  /**
   * Manually add a rule
   */
  async addRule(pattern: string, title: string, category: string, type: 'regex' | 'keyword' = 'regex'): Promise<DefenseRule> {
    const rule = this.ruleBank.createRule(
      title,
      `Manually added rule: ${title}`,
      pattern,
      type === 'keyword' ? RuleType.KEYWORD : RuleType.REGEX,
      category as any,
      'manual'
    );
    rule.status = RuleStatus.ACTIVE; // Manual rules go directly to active
    await this.ruleBank.addRule(rule);
    return rule;
  }

  /**
   * Force trigger an evolution cycle
   */
  async forceEvolution(): Promise<EvolutionResult | null> {
    if (!this.initialized || !this.config.enabled) return null;
    return this.runEvolution();
  }

  /**
   * Persist threshold to file for Dashboard
   */
  private persistThreshold(): void {
    try {
      const thresholdPath = path.join(path.dirname(this.config.rulesPath), 'threshold.json');
      const data = { threshold: this.thresholdController.getThreshold(), updatedAt: Date.now() };
      fs.writeFileSync(thresholdPath, JSON.stringify(data, null, 2));
    } catch (err) {
      logger.error(`[EvolveManager] Failed to persist threshold: ${err}`);
    }
  }

  /**
   * Clean up resources
   */
  async close(): Promise<void> {
    await this.eventStore.close();
    this.initialized = false;
  }
}