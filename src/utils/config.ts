/**
 * Configuration Manager
 * 
 * Configuration priority (highest to lowest):
 * 1. Environment variables
 * 2. Config file (~/.openclaw/clawarmor/config.json)
 * 3. Default values
 */

import { ClawArmorConfig } from '../types';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

/** Config file path */
const CONFIG_FILE_PATH = path.join(os.homedir(), '.openclaw/clawarmor/config.json');

/**
 * Expand ~ to home directory in paths
 */
function expandPath(p: string): string {
  if (p.startsWith('~/')) {
    return path.join(os.homedir(), p.slice(2));
  }
  if (p === '~') {
    return os.homedir();
  }
  return p;
}

/**
 * Load config from file if exists
 */
function loadConfigFile(): Partial<ClawArmorConfig> {
  try {
    if (fs.existsSync(CONFIG_FILE_PATH)) {
      const content = fs.readFileSync(CONFIG_FILE_PATH, 'utf-8');
      const fileConfig = JSON.parse(content);
      // Expand paths in file config
      if (fileConfig.evolveDbPath) {
        fileConfig.evolveDbPath = expandPath(fileConfig.evolveDbPath);
      }
      if (fileConfig.evolveRulesPath) {
        fileConfig.evolveRulesPath = expandPath(fileConfig.evolveRulesPath);
      }
      return fileConfig;
    }
  } catch (err) {
    console.error(`[ClawArmor] Failed to load config file: ${err}`);
  }
  return {};
}

const DEFAULT_CONFIG: ClawArmorConfig = {
  enabled: true,
  blockOnCritical: false,
  blockOnHighRisk: false,
  logAllChecks: false,
  maxInputLength: 10000,
  maskSensitiveData: true,
  // Evolve defaults - use expandPath to resolve ~ to home directory
  evolveEnabled: true,
  evolveDbPath: expandPath('~/.openclaw/clawarmor/events.db'),
  evolveRulesPath: expandPath('~/.openclaw/clawarmor/rules.json'),
  evolveUpdateInterval: 5,
  evolveLlmApiBase: 'https://dashscope.aliyuncs.com/api/v1',
  evolveLlmApiKey: '',
  evolveLlmModel: 'qwen3-coder-plus',
  evolveTargetFpRate: 0.05,
  evolveTargetFnRate: 0.02
};

export class ConfigManager {
  private static config: ClawArmorConfig | null = null;

  static load(): ClawArmorConfig {
    if (this.config) {
      return this.config;
    }

    // Load config file (if exists)
    const fileConfig = loadConfigFile();

    // Load from environment variables
    // Note: only override defaults when env var is explicitly set,
    // to avoid undefined values overwriting valid defaults.
    const envConfig: Partial<ClawArmorConfig> = {
      enabled: process.env.CLAWARMOR_ENABLED !== 'false',
      blockOnCritical: process.env.CLAWARMOR_BLOCK_CRITICAL !== 'false',
      blockOnHighRisk: process.env.CLAWARMOR_BLOCK_HIGH === 'true',
      logAllChecks: process.env.CLAWARMOR_LOG_ALL === 'true',
      maxInputLength: parseInt(process.env.CLAWARMOR_MAX_LENGTH || '10000', 10),
      maskSensitiveData: process.env.CLAWARMOR_MASK_DATA !== 'false',
      // Evolve env vars — use || fallback so undefined never reaches the config
      evolveEnabled: process.env.CLAWARMOR_EVOLVE_ENABLED !== 'false',
      evolveDbPath: expandPath(process.env.CLAWARMOR_EVOLVE_DB_PATH || fileConfig.evolveDbPath || DEFAULT_CONFIG.evolveDbPath),
      evolveRulesPath: expandPath(process.env.CLAWARMOR_EVOLVE_RULES_PATH || fileConfig.evolveRulesPath || DEFAULT_CONFIG.evolveRulesPath),
      evolveUpdateInterval: parseInt(process.env.CLAWARMOR_EVOLVE_INTERVAL || String(fileConfig.evolveUpdateInterval ?? DEFAULT_CONFIG.evolveUpdateInterval), 10),
      evolveLlmApiBase: process.env.CLAWARMOR_EVOLVE_LLM_API_BASE || fileConfig.evolveLlmApiBase || DEFAULT_CONFIG.evolveLlmApiBase,
      evolveLlmApiKey: process.env.CLAWARMOR_EVOLVE_LLM_API_KEY || fileConfig.evolveLlmApiKey || DEFAULT_CONFIG.evolveLlmApiKey,
      evolveLlmModel: process.env.CLAWARMOR_EVOLVE_LLM_MODEL || fileConfig.evolveLlmModel || DEFAULT_CONFIG.evolveLlmModel,
      evolveTargetFpRate: parseFloat(process.env.CLAWARMOR_EVOLVE_TARGET_FP || String(fileConfig.evolveTargetFpRate ?? DEFAULT_CONFIG.evolveTargetFpRate)),
      evolveTargetFnRate: parseFloat(process.env.CLAWARMOR_EVOLVE_TARGET_FN || String(fileConfig.evolveTargetFnRate ?? DEFAULT_CONFIG.evolveTargetFnRate))
    };

    // Merge: defaults < fileConfig < envConfig
    this.config = {
      ...DEFAULT_CONFIG,
      ...fileConfig,
      ...envConfig
    };

    return this.config;
  }

  static reload(): ClawArmorConfig {
    this.config = null;
    return this.load();
  }

  static update(updates: Partial<ClawArmorConfig>): ClawArmorConfig {
    this.config = {
      ...this.load(),
      ...updates
    };
    return this.config;
  }
}
