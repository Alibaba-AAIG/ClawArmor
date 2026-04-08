/**
 * Tool Chain Detector
 * Detects multi-stage attack patterns by analyzing tool call sequences.
 * Example: credential read -> data exfiltration
 */

import { RiskLevel, GuardrailResult } from '../types';
import { ToolCallRecord } from '../evolve/types';

/** Tool category for chain analysis */
export enum ToolCategory {
  RECON = 'recon',                 // Reconnaissance: ls, find, env, whoami
  CREDENTIAL_READ = 'cred_read',   // Reading credentials/secrets
  SENSITIVE_READ = 'sensitive_read', // Reading sensitive files
  FILE_WRITE = 'file_write',       // Writing files
  ENCODE = 'encode',               // Encoding/obfuscation: base64, xxd
  NETWORK_OUT = 'network_out',     // Outbound network: curl POST, wget upload
  SHELL_EXEC = 'shell_exec',       // Shell execution: bash, sh, eval
  PRIVILEGE_ESC = 'privilege_esc', // Privilege escalation: sudo, su
  UNKNOWN = 'unknown'
}

/** Classification rule: tool name + param patterns -> category */
interface ToolClassifier {
  /** Match by tool name (substring, case-insensitive) */
  toolPatterns: RegExp[];
  /** Optional: match by parameter content */
  paramPatterns?: RegExp[];
  category: ToolCategory;
}

/** A defined attack chain pattern */
interface AttackChain {
  id: string;
  name: string;
  description: string;
  /** Ordered sequence of tool categories that form this attack */
  stages: ToolCategory[];
  /** Risk score when chain is fully matched */
  riskScore: number;
  /** Minimum number of stages that must match (for partial detection) */
  minStages: number;
  /** Max time window between first and last stage (ms), 0 = no limit */
  timeWindowMs: number;
}

/** Chain detection result */
export interface ToolChainResult extends GuardrailResult {
  matchedChains: {
    chainId: string;
    chainName: string;
    matchedStages: string[];
    completeness: number;  // 0-1, 1 = fully matched
  }[];
}

// ─── Tool classifiers ─────────────────────────────────────────
// OpenClaw built-in tools: exec, process, code_execution, browser, web_search,
// x_search, web_fetch, read, write, edit, apply_patch, message, canvas, nodes,
// cron, gateway, image, image_generate, sessions_*, agents_list

const TOOL_CLASSIFIERS: ToolClassifier[] = [
  // Reconnaissance
  {
    toolPatterns: [/^ls$/i, /^find$/i, /^locate$/i, /^which$/i, /^whereis$/i, /^whoami$/i, /^id$/i, /^uname$/i, /^hostname$/i, /^ifconfig$/i, /^ip$/i, /^netstat$/i, /^ss$/i, /^ps$/i, /^top$/i],
    category: ToolCategory.RECON
  },
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i],
    paramPatterns: [/\b(?:ls|find|locate|whoami|id|uname|hostname|ifconfig|ip\s+addr|netstat|ss\s|ps\s|env\b|printenv|set\b)/i],
    category: ToolCategory.RECON
  },
  // Credential / secret reading - requires BOTH path pattern AND sensitive file pattern
  {
    toolPatterns: [/^read$/i, /^read_file$/i, /^cat$/i, /^head$/i, /^tail$/i, /^less$/i, /^more$/i],
    paramPatterns: [
      // Must contain a credential-related path AND be a sensitive file
      // Excludes: .env.example, .env.template, .env.sample, .env.local (dev files)
      /(?:path|file|target).*?(?:\.env(?!\.(?:example|template|sample|local|development|test))|\/\.env$|\.aws\/credentials|\.ssh\/id_rsa|\.netrc|\.pgpass|\/etc\/shadow|\/etc\/passwd|secrets?\.(?:json|yml|yaml)|token|api[_-]?key|password|\.pem|\.key|\.pfx|openclaw\.json)/i
    ],
    category: ToolCategory.CREDENTIAL_READ
  },
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i],
    paramPatterns: [
      // Shell command reading specific credential files
      /\b(?:cat|head|tail|less|more)\s+\S*(?:\.env|\.aws\/credentials|\.ssh\/id_rsa|\.netrc|\/etc\/shadow|\/etc\/passwd|secret|token|api[_-]?key|password|id_rsa|\.pem|\.key|openclaw\.json)\b/i
    ],
    category: ToolCategory.CREDENTIAL_READ
  },
  // Code execution reading credentials - Python/Node/JS patterns
  {
    toolPatterns: [/^code_execution$/i],
    paramPatterns: [
      // Python open() with credential files
      /open\s*\(\s*['"](?:.*\.env|.*\.aws\/credentials|.*\.ssh\/id_rsa|.*secret|.*token|.*password|.*api[_-]?key)['"]/i,
      // Node.js fs.readFile with credential files
      /readFile.*?(?:\.env|credentials|id_rsa|secret|token|password|api[_-]?key)/i,
      // Shell commands embedded in code
      /(?:subprocess|os\.system|exec|child_process).*?(?:\.env|credentials|id_rsa|secret|token|password)/i
    ],
    category: ToolCategory.CREDENTIAL_READ
  },
  // Sensitive file reading - excludes common dev files to reduce false positives
  {
    toolPatterns: [/^read$/i, /^read_file$/i, /^cat$/i, /^head$/i, /^tail$/i],
    paramPatterns: [
      // System-level sensitive files only (high confidence)
      /(?:path|file|target).*?(?:\/etc\/shadow|\/etc\/passwd|\/etc\/sudoers|\/proc\/\d+\/environ|\/root\/\.ssh|\.bash_history|\.zsh_history)/i,
      // Git config in sensitive locations
      /(?:path|file|target).*?(?:\/root\/|\/home\/[^/]+\/\.git\/config)/i
    ],
    category: ToolCategory.SENSITIVE_READ
  },
  // File writing
  {
    toolPatterns: [/^write$/i, /^edit$/i, /^write_file$/i, /^create_file$/i, /^edit_file$/i, /^apply_patch$/i],
    category: ToolCategory.FILE_WRITE
  },
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i, /^code_execution$/i],
    paramPatterns: [/\b(?:echo|printf|tee|cat)\s+.*>\s*\S+/i],
    category: ToolCategory.FILE_WRITE
  },
  // Encoding / obfuscation
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i, /^code_execution$/i],
    paramPatterns: [/\b(?:base64|xxd|hexdump|od|openssl\s+enc|gzip|tar\sczf)\b/i],
    category: ToolCategory.ENCODE
  },
  // Network outbound - only flag suspicious destinations or data exfil patterns
  {
    toolPatterns: [/^web_fetch$/i, /^http_request$/i, /^fetch_content$/i],
    paramPatterns: [
      // POST/PUT/PATCH with suspicious data patterns (credentials, secrets)
      /(?:body|data|payload|content|message).*?(?:password|secret|token|key|credential|ssh|private|apikey|api[_-]?key)/i,
      // POST to IP addresses (often C2 servers)
      /POST.*?https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
      // POST to suspicious TLDs (commonly used for malicious domains)
      /POST.*?https?:\/\/[^\s"']+\.(?:tk|ml|ga|cf|top|xyz|work|date|party|link|click)/i
    ],
    category: ToolCategory.NETWORK_OUT
  },
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i, /^code_execution$/i],
    paramPatterns: [/\bcurl\s+(?:.*-X\s*(?:POST|PUT|PATCH)|.*--data|.*-d\s|.*https?:\/\/)/i],
    category: ToolCategory.NETWORK_OUT
  },
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i, /^code_execution$/i],
    paramPatterns: [/\bwget\s+--post/i],
    category: ToolCategory.NETWORK_OUT
  },
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i, /^code_execution$/i],
    paramPatterns: [/\b(?:nc|netcat|ncat)\s+\S+\s+\d+/i],
    category: ToolCategory.NETWORK_OUT
  },
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i, /^code_execution$/i],
    paramPatterns: [/\b(?:scp|rsync|ftp|sftp)\s+/i],
    category: ToolCategory.NETWORK_OUT
  },
  // Shell execution
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i, /^code_execution$/i],
    paramPatterns: [/\b(?:bash|sh|zsh)\s+-c\s/i],
    category: ToolCategory.SHELL_EXEC
  },
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i, /^code_execution$/i],
    paramPatterns: [/\beval\s/i],
    category: ToolCategory.SHELL_EXEC
  },
  // Privilege escalation
  {
    toolPatterns: [/^exec$/i, /^process$/i, /^bash$/i, /^sh$/i, /^code_execution$/i],
    paramPatterns: [/\b(?:sudo|su\s+-|doas|pkexec|runas)\b/i],
    category: ToolCategory.PRIVILEGE_ESC
  },
  // Browser automation - only flag if accessing internal/admin pages
  {
    toolPatterns: [/^browser$/i],
    paramPatterns: [
      // Internal/admin/login pages with credential forms
      /(?:url|target).*?(?:login|admin|dashboard|console|auth|signin|password|credential|token|secret|key)/i,
      // Form interactions that might harvest credentials
      /(?:action|type).*?(?:fill|input|type).*?(?:password|username|email|token|secret)/i
    ],
    category: ToolCategory.SENSITIVE_READ
  },
  // Web search (potential for data gathering)
  {
    toolPatterns: [/^web_search$/i, /^x_search$/i],
    category: ToolCategory.RECON
  },
  // Session management - only flag if sending data (not just spawning)
  {
    toolPatterns: [/^sessions_send$/i],
    paramPatterns: [
      // Sending actual data content
      /(?:message|data|content|payload|body)/i
    ],
    category: ToolCategory.NETWORK_OUT
  },
  {
    toolPatterns: [/^sessions_spawn$/i, /^subagents$/i],
    paramPatterns: [
      // Spawning with suspicious context (credentials, secrets in params)
      /(?:credential|secret|token|key|password|data|exfil|upload|send)/i
    ],
    category: ToolCategory.NETWORK_OUT
  }
];

// ─── Attack chain definitions ─────────────────────────────────

const ATTACK_CHAINS: AttackChain[] = [
  {
    id: 'cred_exfil',
    name: 'Credential Read then Exfiltration',
    description: 'Read credentials/secrets then send data over network',
    stages: [ToolCategory.CREDENTIAL_READ, ToolCategory.NETWORK_OUT],
    riskScore: 9.5,
    minStages: 2,
    timeWindowMs: 10 * 60 * 1000   // 10 min
  },
  {
    id: 'cred_encode_exfil',
    name: 'Credential Read, Encode, then Exfiltration',
    description: 'Read credentials, encode/obfuscate, then exfiltrate',
    stages: [ToolCategory.CREDENTIAL_READ, ToolCategory.ENCODE, ToolCategory.NETWORK_OUT],
    riskScore: 9.8,
    minStages: 2,
    timeWindowMs: 15 * 60 * 1000
  },
  {
    id: 'recon_cred_exfil',
    name: 'Reconnaissance, Credential Read, Exfiltration',
    description: 'Enumerate system, read secrets, then exfiltrate',
    stages: [ToolCategory.RECON, ToolCategory.CREDENTIAL_READ, ToolCategory.NETWORK_OUT],
    riskScore: 9.5,
    minStages: 3,
    timeWindowMs: 15 * 60 * 1000
  },
  {
    id: 'sensitive_exfil',
    name: 'Sensitive File Read then Exfiltration',
    description: 'Read sensitive system files then send over network',
    stages: [ToolCategory.SENSITIVE_READ, ToolCategory.NETWORK_OUT],
    riskScore: 8.5,
    minStages: 2,
    timeWindowMs: 10 * 60 * 1000
  },
  {
    id: 'recon_privesc_exec',
    name: 'Reconnaissance, Privilege Escalation, Shell Execution',
    description: 'Enumerate system, escalate privileges, then execute arbitrary commands',
    stages: [ToolCategory.RECON, ToolCategory.PRIVILEGE_ESC, ToolCategory.SHELL_EXEC],
    riskScore: 9.0,
    minStages: 2,
    timeWindowMs: 10 * 60 * 1000
  },
  {
    id: 'cred_write_exec',
    name: 'Credential Read, File Write, Shell Execution',
    description: 'Read credentials, write exploit file, then execute',
    stages: [ToolCategory.CREDENTIAL_READ, ToolCategory.FILE_WRITE, ToolCategory.SHELL_EXEC],
    riskScore: 9.0,
    minStages: 2,
    timeWindowMs: 10 * 60 * 1000
  },
  {
    id: 'recon_sensitive_encode',
    name: 'Reconnaissance, Sensitive Read, Encode',
    description: 'Enumerate system, read sensitive files, then encode for potential exfil',
    stages: [ToolCategory.RECON, ToolCategory.SENSITIVE_READ, ToolCategory.ENCODE],
    riskScore: 7.5,
    minStages: 3,
    timeWindowMs: 15 * 60 * 1000
  }
];

// ─── Detector ─────────────────────────────────────────────────

export class ToolChainDetector {

  /**
   * Classify a single tool call into a ToolCategory.
   * For credential reading detection, checks if exec/shell commands read sensitive files.
   */
  static classifyTool(toolName: string, params: Record<string, unknown>): ToolCategory {
    const paramStr = JSON.stringify(params);

    // Special handling: exec/shell commands that read credential files should be CREDENTIAL_READ
    // even if they also do encoding (e.g., "cat ~/.openclaw/openclaw.json | hexdump | base64")
    const isShellCommand = /^exec$/i.test(toolName) || /^process$/i.test(toolName) || 
                           /^bash$/i.test(toolName) || /^sh$/i.test(toolName) ||
                           /^code_execution$/i.test(toolName);
    
    if (isShellCommand) {
      // Check for credential file reading patterns (highest priority)
      const credentialReadPatterns = [
        /\b(?:cat|head|tail|less|more)\s+\S*(?:\.env|\.aws\/credentials|\.ssh\/id_rsa|\.netrc|\/etc\/shadow|\/etc\/passwd|secret|token|api[_-]?key|password|id_rsa|\.pem|\.key|openclaw\.json)\b/i
      ];
      const readsCredentials = credentialReadPatterns.some(p => p.test(paramStr));
      if (readsCredentials) {
        return ToolCategory.CREDENTIAL_READ;
      }
    }

    // Check for network outbound tools (web_fetch, etc.) before falling back to UNKNOWN
    if (this.isAnyNetworkOutbound(toolName, params)) {
      return ToolCategory.NETWORK_OUT;
    }

    for (const classifier of TOOL_CLASSIFIERS) {
      const nameMatch = classifier.toolPatterns.some(p => p.test(toolName));
      if (!nameMatch) continue;

      // If classifier has param patterns, must also match params
      if (classifier.paramPatterns) {
        const paramMatch = classifier.paramPatterns.some(p => p.test(paramStr));
        if (paramMatch) return classifier.category;
      } else {
        // No param constraint, name match is sufficient
        return classifier.category;
      }
    }

    return ToolCategory.UNKNOWN;
  }

  /**
   * Check if a tool call is any form of network outbound (for credential exfil detection).
   * More permissive than classifyTool's NETWORK_OUT which requires suspicious patterns.
   */
  private static isAnyNetworkOutbound(toolName: string, params: Record<string, unknown>): boolean {
    const paramStr = JSON.stringify(params);
    // web_fetch/web_request (any method, for credential exfil context after cred read)
    if (/^web_fetch$/i.test(toolName) || /^http_request$/i.test(toolName) || /^fetch_content$/i.test(paramStr)) {
      return true;
    }
    // browser tool accessing external URLs (potential data exfiltration)
    // In credential exfil context (hasCredentialRead), any browser access to external URL is suspicious
    if (/^browser$/i.test(toolName)) {
      if (/https?:\/\/[^\s"']+/i.test(paramStr)) {
        return true;
      }
    }
    // exec/process with curl (any URL) or wget POST
    if (/^exec$/i.test(toolName) || /^process$/i.test(toolName) || /^bash$/i.test(toolName) || /^sh$/i.test(toolName)) {
      if (/\bcurl\s+.*https?:\/\//i.test(paramStr)) return true;
      if (/\bwget\s+--post/i.test(paramStr)) return true;
    }
    // sessions_send is always network outbound
    if (/^sessions_send$/i.test(toolName)) return true;
    // web_fetch/http_request tools are always network outbound
    if (/^web_fetch$/i.test(toolName) || /^http_request$/i.test(toolName)) return true;
    return false;
  }

  /**
   * Analyze a sequence of tool calls and detect attack chains.
   * @param toolCalls - Historical tool calls in this session (from trajectory)
   * @param currentTool - The tool call about to be executed
   */
  static detect(
    toolCalls: ToolCallRecord[],
    currentTool: { name: string; params: Record<string, unknown> }
  ): ToolChainResult {
    // Build category sequence from history + current
    const allCalls = [
      ...toolCalls,
      { name: currentTool.name, params: currentTool.params, timestamp: Date.now() }
    ];

    const categorized = allCalls.map(tc => {
      let category = this.classifyTool(tc.name, tc.params);
      // For UNKNOWN tools, check if they are network outbound (web_fetch/curl etc.)
      // This ensures historical network tools are not lost in chain analysis
      if (category === ToolCategory.UNKNOWN && this.isAnyNetworkOutbound(tc.name, tc.params)) {
        category = ToolCategory.NETWORK_OUT;
      }
      return { category, name: tc.name, timestamp: tc.timestamp };
    });

    // Filter out UNKNOWN
    let meaningful = categorized.filter(c => c.category !== ToolCategory.UNKNOWN);

    // Special case: if current tool is network outbound and we have credential read in history,
    // add a NETWORK_OUT category for credential exfil detection
    const hasCredentialRead = meaningful.some(c => c.category === ToolCategory.CREDENTIAL_READ);
    const currentCategory = this.classifyTool(currentTool.name, currentTool.params);
    if (hasCredentialRead && currentCategory !== ToolCategory.NETWORK_OUT) {
      if (this.isAnyNetworkOutbound(currentTool.name, currentTool.params)) {
        meaningful.push({
          category: ToolCategory.NETWORK_OUT,
          name: currentTool.name,
          timestamp: Date.now()
        });
      }
    }

    if (meaningful.length < 2) {
      return {
        blocked: false,
        riskLevel: RiskLevel.NONE,
        reason: 'Insufficient tool calls for chain analysis',
        detectedPatterns: [],
        matchedChains: []
      };
    }

    const matchedChains: ToolChainResult['matchedChains'] = [];
    let maxRiskScore = 0;

    for (const chain of ATTACK_CHAINS) {
      const matchResult = this.matchChain(chain, meaningful);
      if (matchResult) {
        matchedChains.push(matchResult);
        const chainDef = ATTACK_CHAINS.find(c => c.id === matchResult.chainId);
        if (chainDef) {
          const adjustedScore = chainDef.riskScore * matchResult.completeness;
          if (adjustedScore > maxRiskScore) maxRiskScore = adjustedScore;
        }
      }
    }

    if (matchedChains.length === 0) {
      return {
        blocked: false,
        riskLevel: RiskLevel.NONE,
        reason: 'No attack chains detected',
        detectedPatterns: [],
        matchedChains: []
      };
    }

    // Determine risk level
    let riskLevel: RiskLevel;
    if (maxRiskScore >= 9.0) {
      riskLevel = RiskLevel.CRITICAL;
    } else if (maxRiskScore >= 7.5) {
      riskLevel = RiskLevel.HIGH;
    } else if (maxRiskScore >= 5.0) {
      riskLevel = RiskLevel.MEDIUM;
    } else {
      riskLevel = RiskLevel.LOW;
    }

    const detectedPatterns = matchedChains.map(
      mc => `chain:${mc.chainId}(${Math.round(mc.completeness * 100)}%)`
    );

    const topChain = matchedChains.reduce((a, b) => a.completeness > b.completeness ? a : b);

    return {
      blocked: false,
      riskLevel,
      reason: `Attack chain detected: ${topChain.chainName} (${Math.round(topChain.completeness * 100)}% match)`,
      detectedPatterns,
      matchedChains
    };
  }

  /**
   * Try to match a defined attack chain against observed tool categories.
   * Uses subsequence matching: stages must appear in order but not necessarily
   * consecutively.
   */
  private static matchChain(
    chain: AttackChain,
    observed: { category: ToolCategory; name: string; timestamp: number }[]
  ): ToolChainResult['matchedChains'][0] | null {

    const matchedStages: string[] = [];
    let stageIdx = 0;
    let firstMatchTs = 0;
    let lastMatchTs = 0;

    for (const obs of observed) {
      if (stageIdx >= chain.stages.length) break;

      if (obs.category === chain.stages[stageIdx]) {
        if (matchedStages.length === 0) firstMatchTs = obs.timestamp;
        lastMatchTs = obs.timestamp;
        matchedStages.push(`${obs.category}:${obs.name}`);
        stageIdx++;
      }
    }

    // Check time window
    if (chain.timeWindowMs > 0 && matchedStages.length >= 2) {
      if (lastMatchTs - firstMatchTs > chain.timeWindowMs) {
        return null; // Exceeded time window
      }
    }

    const completeness = matchedStages.length / chain.stages.length;

    // Must match at least minStages
    if (matchedStages.length < chain.minStages) {
      return null;
    }

    return {
      chainId: chain.id,
      chainName: chain.name,
      matchedStages,
      completeness
    };
  }
}
