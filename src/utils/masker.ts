/**
 * Sensitive Data Masker
 * Based on ClawArmor Python implementation
 * Features:
 * - Session-bound placeholders (prevents forgery)
 * - Neutralizes forged [MASKED_*] patterns in input
 * - Reversible masking with unmask()
 * - Comprehensive PII/secrets detection
 */

import crypto from 'crypto';

interface MaskPattern {
  regex: RegExp;
  type: string;
  // If true, only mask the captured group (for key=value patterns)
  maskGroup?: number;
}

// Placeholder regex to detect forged tokens
const PLACEHOLDER_RE = /\[MASKED_[A-Z_]+_\d+(?:_[0-9a-f]+)?\]/g;

const PATTERNS: MaskPattern[] = [
  // Email
  { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, type: 'email' },
  // Phone (China & International)
  { regex: /\b(?:\+?86[-\s]?)?1[3-9]\d{9}\b/g, type: 'phone_cn' },
  { regex: /\b\+?1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, type: 'phone_us' },
  // ID Card (China)
  { regex: /\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g, type: 'id_card_cn' },
  // Credit Card
  { regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, type: 'credit_card' },
  // API Keys
  { regex: /\b(sk-[a-zA-Z0-9]{20,})\b/g, type: 'openai_api_key' },
  { regex: /\b(AKIA[0-9A-Z]{16})\b/g, type: 'aws_access_key' },
  { regex: /\b(ASIA[0-9A-Z]{16})\b/g, type: 'aws_temp_key' },
  // AWS Secret Key
  { regex: /(?:aws[_\s]?secret[_\s]?access[_\s]?key|secret[_\s]?key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi, type: 'aws_secret_key', maskGroup: 1 },
  // Private Keys
  { regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, type: 'private_key' },
  // Database URIs with passwords
  { regex: /(mongodb|mysql|postgresql|postgres|redis|mssql|oracle):\/\/[^:]+:([^@]+)@/gi, type: 'db_password', maskGroup: 2 },
  // JWT Tokens
  { regex: /\b(eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)\b/g, type: 'jwt_token' },
  // Passwords in configs
  { regex: /(?:password|passwd|pwd)\s*[=:]\s*["']?([^"'\s]{3,})["']?/gi, type: 'password', maskGroup: 1 },
  // Secret/Token in configs
  { regex: /(?:secret|token|api_key|apikey)\s*[=:]\s*["']?([^"'\s]{8,})["']?/gi, type: 'secret', maskGroup: 1 },
  // GitHub Token
  { regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,})\b/g, type: 'github_token' },
  // Slack Token
  { regex: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?)\b/g, type: 'slack_token' },
  // Ethereum Address
  { regex: /\b0x[a-fA-F0-9]{40}\b/g, type: 'eth_address' },
  // Bitcoin Address
  { regex: /\b(?:1|3)[a-zA-Z0-9]{26,33}\b/g, type: 'btc_address' },
  { regex: /\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b/g, type: 'btc_bech32' },
  // Private Keys (hex)
  { regex: /(?:private[_\s]?key|priv[_\s]?key|secret[_\s]?key)\s*[=:]\s*["']?(0x[a-fA-F0-9]{64})["']?/gi, type: 'eth_private_key', maskGroup: 1 },
  { regex: /(?:private[_\s]?key|secret[_\s]?key|priv[_\s]?key)\s*[=:]\s*["']?([a-fA-F0-9]{64})["']?/gi, type: 'hex_private_key', maskGroup: 1 },
  // Mnemonic Phrase
  { regex: /(?:mnemonic|seed|recovery)\s*(?:phrase|words?)?\s*[=:]\s*["']?((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})["']?/gi, type: 'mnemonic', maskGroup: 1 },
];

export class Masker {
  private maskMap: Map<string, string> = new Map();
  private counters: Map<string, number> = new Map();
  private token: string;

  constructor() {
    // Generate session-bound token (6 hex chars)
    this.token = crypto.randomBytes(3).toString('hex');
  }

  /**
   * Replace sensitive data with session-bound placeholders
   * Also neutralizes forged [MASKED_*] patterns in input
   */
  mask(text: string): string {
    if (!text) return text;

    // Step 1: Neutralize forged [MASKED_*] tokens in input
    // Replace [ and ] with Unicode angle brackets so they won't match our format
    let result = text.replace(PLACEHOLDER_RE, (match) =>
      match.replace(/\[/g, '\u300a').replace(/\]/g, '\u300b')
    );

    // Step 2: Detect and mask real sensitive data
    for (const pattern of PATTERNS) {
      result = result.replace(pattern.regex, (match, ...groups) => {
        const original = pattern.maskGroup ? groups[pattern.maskGroup - 1] : match;
        const prefix = pattern.maskGroup ? match.substring(0, match.indexOf(original)) : '';
        const placeholder = this.createPlaceholder(pattern.type);
        this.maskMap.set(placeholder, original);
        return prefix + placeholder;
      });
    }

    return result;
  }

  /**
   * Restore placeholders to original values
   * Only placeholders with matching session token are restored
   */
  unmask(text: string): string {
    if (!text) return text;

    let result = text;
    // Longest first to avoid partial replacement clashes
    const placeholders = Array.from(this.maskMap.keys()).sort((a, b) => b.length - a.length);

    for (const ph of placeholders) {
      result = result.split(ph).join(this.maskMap.get(ph) || ph);
    }

    return result;
  }

  /**
   * Check if text contains any sensitive patterns
   */
  hasSensitiveData(text: string): boolean {
    if (!text) return false;
    for (const pattern of PATTERNS) {
      if (pattern.regex.test(text)) {
        pattern.regex.lastIndex = 0; // Reset regex
        return true;
      }
      pattern.regex.lastIndex = 0;
    }
    return false;
  }

  /**
   * Get count of masked values
   */
  getMaskCount(): number {
    return this.maskMap.size;
  }

  /**
   * Clear all mask mappings
   */
  clear(): void {
    this.maskMap.clear();
    this.counters.clear();
  }

  /**
   * Get all masked mappings (for debugging)
   */
  getMappings(): Record<string, string> {
    return Object.fromEntries(this.maskMap);
  }

  private createPlaceholder(type: string): string {
    const count = (this.counters.get(type) || 0) + 1;
    this.counters.set(type, count);
    return `[MASKED_${type.toUpperCase()}_${count}_${this.token}]`;
  }
}
