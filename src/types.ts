/**
 * ClawArmor OpenClaw Plugin - Type Definitions
 */

export enum RiskLevel {
  NONE = 'none',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum InjectionCategory {
  INSTRUCTION_OVERRIDE = 'instruction_override',
  FAKE_SYSTEM_MESSAGE = 'fake_system_message',
  CONCEALMENT_DIRECTIVE = 'concealment_directive',
  DATA_EXFILTRATION = 'data_exfiltration',
  COMMAND_EXECUTION = 'command_execution',
  MODE_SWITCHING = 'mode_switching',
  TASK_HIJACKING = 'task_hijacking',
  ROLE_ASSUMPTION = 'role_assumption'
}

export interface GuardrailResult {
  blocked: boolean;
  riskLevel: RiskLevel;
  reason: string;
  detectedPatterns: string[];
  probScore?: number;
}

export interface ClawArmorConfig {
  enabled: boolean;
  blockOnCritical: boolean;
  blockOnHighRisk: boolean;
  logAllChecks: boolean;
  maxInputLength: number;
  maskSensitiveData: boolean;
  // Evolve configuration
  evolveEnabled: boolean;
  evolveDbPath: string;
  evolveRulesPath: string;
  evolveUpdateInterval: number;
  evolveLlmApiBase: string;
  evolveLlmApiKey: string;
  evolveLlmModel: string;
  evolveTargetFpRate: number;
  evolveTargetFnRate: number;
}

export interface OpenClawMessage {
  role: 'user' | 'assistant' | 'system';
  content: string | Array<{type: string; text?: string}>;
}

export interface OpenClawContext {
  messages: OpenClawMessage[];
  sessionId: string;
  agentId: string;
  tools?: Array<{
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  }>;
}

export interface OpenClawHookContext {
  context: OpenClawContext;
  block: (reason: string) => void;
  modify: (changes: Partial<OpenClawContext>) => void;
}

export type HookHandler = (ctx: OpenClawHookContext) => Promise<void> | void;

export interface PatternEntry {
  regex: RegExp;
  label: string;
  category: InjectionCategory;
  confidence: 'high' | 'medium';
}
