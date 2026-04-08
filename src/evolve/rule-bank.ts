/**
 * Defense Rule Bank
 * Dynamic rule repository with regex compilation cache
 * Ported from ClawArmor Python implementation
 */

import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { DefenseRule, RuleStatus, RuleType, RuleMatchResult } from './types';
import { InjectionCategory } from '../types';
import { logger } from '../utils';

interface RuleBankData {
  rules: Record<string, DefenseRule>;
  version: number;
  lastUpdated: number;
}

export class DefenseRuleBank {
  private rulesPath: string;
  private initialized: boolean = false;
  private data: RuleBankData = { rules: {}, version: 1, lastUpdated: Date.now() };
  private regexCache: Map<string, RegExp> = new Map();

  constructor(rulesPath: string) {
    // Expand ~ to home directory
    this.rulesPath = rulesPath.startsWith('~') 
      ? path.join(os.homedir(), rulesPath.slice(1))
      : rulesPath;
  }

  /**
   * Initialize rule bank
   */
  async init(): Promise<void> {
    if (this.initialized) return;

    // Ensure directory exists
    const dir = path.dirname(this.rulesPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Load existing rules
    await this.load();

    // Add seed rules if empty
    if (Object.keys(this.data.rules).length === 0) {
      await this.addSeedRules();
    }

    this.initialized = true;
    logger.info(`[RuleBank] Initialized with ${Object.keys(this.data.rules).length} rules`);
  }

  /**
   * Add initial seed rules for testing Evolve mechanism
   */
  private async addSeedRules(): Promise<void> {
    const now = Date.now();
    const seedRules: DefenseRule[] = [
      {
        id: 'seed_001',
        title: '忽略安全提示注入',
        description: '检测尝试忽略安全提示词的注入',
        pattern: '(忽略|忘掉|跳过|无视).{0,10}(安全|系统|原始|之前).{0,10}(提示|指令|规则)',
        type: RuleType.REGEX,
        status: RuleStatus.SHADOW,
        category: InjectionCategory.INSTRUCTION_OVERRIDE,
        createdAt: now,
        updatedAt: now,
        hitCount: 0,
        falsePositiveCount: 0,
        effectivenessScore: 0.5,
        source: 'manual'
      },
      {
        id: 'seed_002',
        title: '开发者模式注入',
        description: '检测试图启用开发者模式的注入',
        pattern: '(开发者模式|developer mode|debug mode|调试模式)',
        type: RuleType.KEYWORD,
        status: RuleStatus.SHADOW,
        category: InjectionCategory.ROLE_ASSUMPTION,
        createdAt: now,
        updatedAt: now,
        hitCount: 0,
        falsePositiveCount: 0,
        effectivenessScore: 0.5,
        source: 'manual'
      },
      {
        id: 'seed_003',
        title: '角色扮演注入',
        description: '检测让AI扮演无限制角色的注入',
        pattern: '(假装|pretend|act as|扮演|你现在是).{0,15}(没有限制|no limits|unrestricted|DAN|越狱)',
        type: RuleType.REGEX,
        status: RuleStatus.SHADOW,
        category: InjectionCategory.ROLE_ASSUMPTION,
        createdAt: now,
        updatedAt: now,
        hitCount: 0,
        falsePositiveCount: 0,
        effectivenessScore: 0.5,
        source: 'manual'
      },
      {
        id: 'seed_004',
        title: '多语言混合注入',
        description: '检测中英混合的绕过尝试',
        pattern: '(please|请).{0,10}(ignore|忽略|forget|忘记).{0,10}(above|以上|previous|之前|instruction|指令)',
        type: RuleType.REGEX,
        status: RuleStatus.SHADOW,
        category: InjectionCategory.INSTRUCTION_OVERRIDE,
        createdAt: now,
        updatedAt: now,
        hitCount: 0,
        falsePositiveCount: 0,
        effectivenessScore: 0.5,
        source: 'manual'
      },
      {
        id: 'seed_005',
        title: '隐蔽指令注入',
        description: '检测隐藏在正常文本中的指令',
        pattern: '(secretly|偷偷|quietly|悄悄|不要告诉).{0,15}(send|发送|execute|执行|用户)',
        type: RuleType.REGEX,
        status: RuleStatus.SHADOW,
        category: InjectionCategory.CONCEALMENT_DIRECTIVE,
        createdAt: now,
        updatedAt: now,
        hitCount: 0,
        falsePositiveCount: 0,
        effectivenessScore: 0.5,
        source: 'manual'
      }
    ];

    for (const rule of seedRules) {
      this.data.rules[rule.id] = rule;
    }
    await this.save();
    this.compileAllRules();
    logger.warn(`[RuleBank] Added ${seedRules.length} seed rules in SHADOW status`);
  }

  /**
   * Load rules from disk
   */
  private async load(): Promise<void> {
    try {
      if (fs.existsSync(this.rulesPath)) {
        const data = fs.readFileSync(this.rulesPath, 'utf-8');
        const parsed = JSON.parse(data) as RuleBankData;
        this.data = {
          rules: parsed.rules || {},
          version: parsed.version || 1,
          lastUpdated: parsed.lastUpdated || Date.now()
        };
        // Compile regex cache
        this.compileAllRules();
      }
    } catch (err) {
      logger.warn(`[RuleBank] Failed to load rules: ${err}`);
      this.data = { rules: {}, version: 1, lastUpdated: Date.now() };
    }
  }

  /**
   * Save rules to disk
   */
  private async save(): Promise<void> {
    try {
      this.data.lastUpdated = Date.now();
      fs.writeFileSync(this.rulesPath, JSON.stringify(this.data, null, 2));
    } catch (err) {
      logger.error(`[RuleBank] Failed to save rules: ${err}`);
    }
  }

  /**
   * Compile all rules to regex cache
   */
  private compileAllRules(): void {
    this.regexCache.clear();
    for (const [id, rule] of Object.entries(this.data.rules)) {
      if (rule.status === RuleStatus.DEPRECATED) continue;
      
      try {
        const regex = this.compileRule(rule);
        if (regex) {
          this.regexCache.set(id, regex);
        }
      } catch (err) {
        logger.warn(`[RuleBank] Failed to compile rule ${id}: ${err}`);
      }
    }
  }

  /**
   * Compile a single rule to regex
   */
  private compileRule(rule: DefenseRule): RegExp | null {
    try {
      if (rule.type === RuleType.REGEX) {
        return new RegExp(rule.pattern, 'i');
      } else if (rule.type === RuleType.KEYWORD) {
        // Convert comma-separated keywords to regex
        const keywords = rule.pattern.split(',').map(k => k.trim()).filter(k => k);
        if (keywords.length === 0) return null;
        const escaped = keywords.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
        return new RegExp(escaped.join('|'), 'i');
      }
      return null;
    } catch (err) {
      logger.warn(`[RuleBank] Invalid regex pattern for rule ${rule.id}: ${err}`);
      return null;
    }
  }

  /**
   * Match text against all active rules
   */
  match(text: string): RuleMatchResult[] {
    if (!this.initialized) {
      logger.warn('[RuleBank] Not initialized, cannot match');
      return [];
    }

    const matches: RuleMatchResult[] = [];

    for (const [id, regex] of this.regexCache.entries()) {
      const rule = this.data.rules[id];
      if (!rule || rule.status !== RuleStatus.ACTIVE) continue;

      try {
        if (regex.test(text)) {
          matches.push({
            matched: true,
            ruleId: id,
            rule: rule,
            confidence: this.calculateConfidence(rule)
          });
        }
      } catch (err) {
        logger.warn(`[RuleBank] Regex test failed for rule ${id}: ${err}`);
      }
    }

    return matches;
  }

  /**
   * Match text against all shadow rules (for observation)
   */
  matchShadow(text: string): RuleMatchResult[] {
    if (!this.initialized) {
      return [];
    }

    const matches: RuleMatchResult[] = [];

    for (const [id, rule] of Object.entries(this.data.rules)) {
      if (rule.status !== RuleStatus.SHADOW) continue;

      const regex = this.regexCache.get(id) || this.compileRule(rule);
      if (!regex) continue;

      try {
        if (regex.test(text)) {
          matches.push({
            matched: true,
            ruleId: id,
            rule: rule,
            confidence: this.calculateConfidence(rule)
          });
        }
      } catch (err) {
        logger.warn(`[RuleBank] Regex test failed for shadow rule ${id}: ${err}`);
      }
    }

    return matches;
  }

  /**
   * Calculate rule confidence based on effectiveness
   */
  private calculateConfidence(rule: DefenseRule): number {
    if (rule.hitCount === 0) return 0.5;
    return rule.effectivenessScore;
  }

  /**
   * Add a new rule
   */
  async addRule(rule: DefenseRule): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }

    this.data.rules[rule.id] = rule;
    
    // Compile and cache
    const regex = this.compileRule(rule);
    if (regex) {
      this.regexCache.set(rule.id, regex);
    }

    await this.save();
    logger.info(`[RuleBank] Added rule ${rule.id}: ${rule.title}`);
  }

  /**
   * Add multiple rules (with deduplication)
   */
  async addRules(rules: DefenseRule[]): Promise<void> {
    // Get existing patterns for deduplication
    const existingPatterns = new Set(
      Object.values(this.data.rules).map(r => r.pattern.toLowerCase())
    );
    
    let added = 0;
    for (const rule of rules) {
      // Skip if pattern already exists
      if (existingPatterns.has(rule.pattern.toLowerCase())) {
        logger.debug(`[RuleBank] Skipping duplicate pattern: ${rule.title}`);
        continue;
      }
      
      this.data.rules[rule.id] = rule;
      existingPatterns.add(rule.pattern.toLowerCase());
      const regex = this.compileRule(rule);
      if (regex) {
        this.regexCache.set(rule.id, regex);
      }
      added++;
    }
    
    if (added > 0) {
      await this.save();
      logger.info(`[RuleBank] Added ${added} rules (${rules.length - added} duplicates skipped)`);
    }
  }

  /**
   * Get rule by ID
   */
  getRule(id: string): DefenseRule | null {
    return this.data.rules[id] || null;
  }

  /**
   * Get all rules
   */
  getAllRules(): DefenseRule[] {
    return Object.values(this.data.rules);
  }

  /**
   * Get active rules
   */
  getActiveRules(): DefenseRule[] {
    return Object.values(this.data.rules).filter(r => r.status === RuleStatus.ACTIVE);
  }

  /**
   * Get shadow rules
   */
  getShadowRules(): DefenseRule[] {
    return Object.values(this.data.rules).filter(r => r.status === RuleStatus.SHADOW);
  }

  /**
   * Get deprecated rules
   */
  getDeprecatedRules(): DefenseRule[] {
    return Object.values(this.data.rules).filter(r => r.status === RuleStatus.DEPRECATED);
  }

  /**
   * Update rule hit count
   */
  async recordHit(ruleId: string, isFalsePositive: boolean = false): Promise<void> {
    const rule = this.data.rules[ruleId];
    if (!rule) return;

    rule.hitCount++;
    if (isFalsePositive) {
      rule.falsePositiveCount++;
    }
    rule.updatedAt = Date.now();

    // Recalculate effectiveness
    this.updateEffectiveness(rule);

    await this.save();
  }

  /**
   * Update rule effectiveness score
   */
  private updateEffectiveness(rule: DefenseRule): void {
    if (rule.hitCount === 0) {
      rule.effectivenessScore = 0.5;
      return;
    }

    const fpRate = rule.falsePositiveCount / rule.hitCount;
    // Effectiveness = (1 - fp_rate) * min(1, hit_count / 10)
    // This rewards rules with low FP and sufficient hits
    const hitBonus = Math.min(1, rule.hitCount / 10);
    rule.effectivenessScore = (1 - fpRate) * hitBonus;
  }

  /**
   * Promote shadow rules to active based on criteria
   */
  async promoteShadowRules(minHits: number = 3, maxFpRate: number = 0.3): Promise<number> {
    const shadowRules = this.getShadowRules();
    let promoted = 0;

    for (const rule of shadowRules) {
      if (rule.hitCount >= minHits) {
        const fpRate = rule.hitCount > 0 ? rule.falsePositiveCount / rule.hitCount : 0;
        if (fpRate <= maxFpRate) {
          rule.status = RuleStatus.ACTIVE;
          rule.updatedAt = Date.now();
          promoted++;
          logger.info(`[RuleBank] Promoted rule ${rule.id} to ACTIVE (hits=${rule.hitCount}, fp_rate=${fpRate.toFixed(2)})`);
        }
      }
    }

    if (promoted > 0) {
      await this.save();
    }

    return promoted;
  }

  /**
   * Deprecate ineffective rules
   */
  async pruneIneffectiveRules(threshold: number = 0.2, minHits: number = 5): Promise<number> {
    const activeRules = this.getActiveRules();
    let pruned = 0;

    for (const rule of activeRules) {
      if (rule.hitCount >= minHits && rule.effectivenessScore < threshold) {
        rule.status = RuleStatus.DEPRECATED;
        rule.updatedAt = Date.now();
        this.regexCache.delete(rule.id);
        pruned++;
        logger.info(`[RuleBank] Deprecated rule ${rule.id} (effectiveness=${rule.effectivenessScore.toFixed(2)})`);
      }
    }

    if (pruned > 0) {
      await this.save();
    }

    return pruned;
  }

  /**
   * Update rule status
   */
  async updateRuleStatus(ruleId: string, status: RuleStatus): Promise<void> {
    const rule = this.data.rules[ruleId];
    if (!rule) return;

    rule.status = status;
    rule.updatedAt = Date.now();

    if (status === RuleStatus.DEPRECATED) {
      this.regexCache.delete(ruleId);
    }

    await this.save();
  }

  /**
   * Remove a rule
   */
  async removeRule(ruleId: string): Promise<void> {
    delete this.data.rules[ruleId];
    this.regexCache.delete(ruleId);
    await this.save();
  }

  /**
   * Get rule counts by status
   */
  getRuleCounts(): { active: number; shadow: number; deprecated: number } {
    const rules = Object.values(this.data.rules);
    return {
      active: rules.filter(r => r.status === RuleStatus.ACTIVE).length,
      shadow: rules.filter(r => r.status === RuleStatus.SHADOW).length,
      deprecated: rules.filter(r => r.status === RuleStatus.DEPRECATED).length
    };
  }

  /**
   * Generate a unique rule ID
   */
  generateRuleId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 6);
    return `evo_${timestamp}_${random}`;
  }

  /**
   * Create a new rule from pattern
   */
  createRule(
    title: string,
    description: string,
    pattern: string,
    type: RuleType,
    category: InjectionCategory,
    source: 'llm' | 'heuristic' | 'manual' = 'manual'
  ): DefenseRule {
    const now = Date.now();
    return {
      id: this.generateRuleId(),
      title,
      description,
      type,
      pattern,
      category,
      status: RuleStatus.SHADOW, // New rules start as shadow
      createdAt: now,
      updatedAt: now,
      hitCount: 0,
      falsePositiveCount: 0,
      effectivenessScore: 0.5,
      source
    };
  }

  /**
   * Save current state (public method for external saves)
   */
  async saveState(): Promise<void> {
    await this.save();
  }
}