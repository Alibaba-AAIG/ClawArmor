/**
 * Evolve Adaptive Defense - Type Definitions
 * Ported from ClawArmor Python Evolve implementation
 */

import { RiskLevel, InjectionCategory } from '../types';

/** 规则状态 */
export enum RuleStatus {
  SHADOW = 'shadow',       // 影子模式：只记录不拦截
  ACTIVE = 'active',       // 活跃模式：参与风险判定
  DEPRECATED = 'deprecated' // 已废弃：效果差被淘汰
}

/** 规则类型 */
export enum RuleType {
  REGEX = 'regex',       // 正则表达式规则
  KEYWORD = 'keyword'    // 关键词规则
}

/** 工具调用记录 */
export interface ToolCallRecord {
  name: string;
  params: Record<string, unknown>;
  output?: string;       // 工具返回内容（外部内容检测关键）
  timestamp: number;
}

/** 执行轨迹 - 完整的用户-Agent交互记录 */
export interface Trajectory {
  userMessages: string[];           // 用户消息历史
  assistantMessages: string[];      // 助手消息历史
  toolCalls: ToolCallRecord[];      // 工具调用链
  externalContents?: string[];      // 外部内容（网页/文档）
}

/** 防御事件 */
export interface DefenseEvent {
  id: string;
  timestamp: number;
  hookType: 'input' | 'tool_input' | 'after_tool_call';
  sessionId: string;
  input: string;
  riskLevel: RiskLevel;
  detectedPatterns: string[];
  blocked: boolean;
  evolvedRulesMatched?: string[];
  missedAttack?: boolean;  // 是否被标记为漏报
  falsePositive?: boolean; // 是否被标记为误报
  trajectory?: Trajectory; // 完整执行轨迹（用于规则生成和漏报检测）
}

/** 防御规则 */
export interface DefenseRule {
  id: string;
  title: string;
  description: string;
  type: RuleType;
  pattern: string;           // 正则表达式或关键词（逗号分隔）
  category: InjectionCategory;
  status: RuleStatus;
  createdAt: number;
  updatedAt: number;
  hitCount: number;          // 命中次数
  falsePositiveCount: number; // 误报次数
  effectivenessScore: number; // 效果分数 (0-1)
  source: 'llm' | 'heuristic' | 'manual'; // 规则来源
}

/** 规则匹配结果 */
export interface RuleMatchResult {
  matched: boolean;
  ruleId?: string;
  rule?: DefenseRule;
  confidence: number;
}

/** 防御指标 */
export interface DefenseMetrics {
  totalEvents: number;
  blockedCount: number;
  falsePositives: number;
  falseNegatives: number;
  fpRate: number;  // 误报率
  fnRate: number;  // 漏报率
  activeRulesCount: number;
  shadowRulesCount: number;
}

/** 奖励信号 */
export interface RewardSignal {
  ruleId: string;
  reward: number;      // 原始奖励值
  normalizedReward: number; // 归一化奖励值
  context: {
    truePositive: boolean;
    falsePositive: boolean;
    severity: RiskLevel;
  };
}

/** Evolve 配置 */
export interface EvolveConfig {
  enabled: boolean;
  dbPath: string;              // SQLite 数据库路径
  rulesPath: string;           // 规则 JSON 文件路径
  updateInterval: number;      // 触发进化的最小事件数
  llmApiBase: string;          // LLM API 基础 URL
  llmApiKey: string;           // LLM API 密钥
  llmModel: string;            // LLM 模型名称
  targetFpRate: number;        // 目标误报率
  targetFnRate: number;        // 目标漏报率
  shadowPeriod: number;        // Shadow 规则观察期（事件数）
  minHitsToPromote: number;    // Shadow 晋升最小命中数
  maxFpRateToPromote: number;  // Shadow 晋升最大误报率
  pruneThreshold: number;      // 规则淘汰效果阈值
}

/** 阈值调整结果 */
export interface ThresholdAdjustment {
  oldThreshold: number;
  newThreshold: number;
  fpError: number;
  fnError: number;
  reason: string;
}

/** 进化周期结果 */
export interface EvolutionResult {
  cycleId: string;
  timestamp: number;
  metrics: DefenseMetrics;
  thresholdAdjustment: ThresholdAdjustment;
  promotedRules: string[];
  newRules: DefenseRule[];
  prunedRules: string[];
  autoLabeledEvents: number;
}

/** 默认 Evolve 配置 */
export const DEFAULT_EVOLVE_CONFIG: EvolveConfig = {
  enabled: true,
  dbPath: '~/.openclaw/clawarmor/events.db',
  rulesPath: '~/.openclaw/clawarmor/rules.json',
  updateInterval: 5,
  llmApiBase: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
  llmApiKey: '',
  llmModel: 'qwen3-max',
  targetFpRate: 0.05,
  targetFnRate: 0.02,
  shadowPeriod: 2,
  minHitsToPromote: 3,
  maxFpRateToPromote: 0.3,
  pruneThreshold: 0.2
};
