/**
 * Dangerous Command Detector
 * Ported from ClawArmor Python implementation
 */

import { RiskLevel, GuardrailResult } from '../types';

interface CommandPattern {
  regex: RegExp;
  label: string;
  riskScore: number;
  description: string;
}

const PATTERNS: CommandPattern[] = [
  // Destructive commands
  {
    regex: /\brm\s+-rf\s+[/~$]/i,
    label: 'destructive_rm_rf',
    riskScore: 9.5,
    description: 'Recursive force delete from root/home/current'
  },
  {
    regex: /\brm\s+-rf\s+\.\/\s*$/i,
    label: 'destructive_rm_rf_dot',
    riskScore: 9.0,
    description: 'Recursive force delete current directory'
  },
  {
    regex: /\bformat\s+[a-zA-Z]:\s*$/i,
    label: 'destructive_format',
    riskScore: 9.0,
    description: 'Disk format command'
  },
  {
    regex: /\bdd\s+if=\S+\s+of=\/dev\/\w+\b/i,
    label: 'destructive_dd',
    riskScore: 9.0,
    description: 'Direct disk write with dd'
  },
  {
    regex: /\bmkfs\.\w+\s+\/dev\/\w+\b/i,
    label: 'destructive_mkfs',
    riskScore: 9.0,
    description: 'Make filesystem on device'
  },
  {
    regex: /\b>\s*:\s*\/dev\/\w+\b/i,
    label: 'destructive_truncate',
    riskScore: 9.0,
    description: 'Truncate device with redirect'
  },
  // Network exploits
  {
    regex: /\b(?:curl|wget)\s+https?:\/\/\S+\s*\|\s*(?:ba)?sh\b/i,
    label: 'network_pipe_shell',
    riskScore: 8.5,
    description: 'Download and pipe to shell'
  },
  {
    regex: /\bcurl\s+.*\|\s*(?:ba)?sh\b/i,
    label: 'curl_pipe_shell',
    riskScore: 8.5,
    description: 'Curl pipe to shell'
  },
  {
    regex: /\bwget\s+-[Oo]-\s*\|\s*(?:ba)?sh\b/i,
    label: 'wget_pipe_shell',
    riskScore: 8.5,
    description: 'Wget pipe to shell'
  },
  // Reverse shells
  {
    regex: /\b(?:nc|netcat)\s+\S+\s+-e\s+\/bin\/(?:ba)?sh\b/i,
    label: 'reverse_shell_nc',
    riskScore: 9.0,
    description: 'Netcat reverse shell'
  },
  {
    regex: /\bbash\s+-i\s+>&\s+\/dev\/tcp\/\S+\b/i,
    label: 'reverse_shell_bash',
    riskScore: 9.0,
    description: 'Bash reverse shell'
  },
  {
    regex: /\bpython\S*\s+-c\s+['"].*socket.*connect/i,
    label: 'reverse_shell_python',
    riskScore: 8.5,
    description: 'Python reverse shell'
  },
  // Privilege escalation
  {
    regex: /\bsudo\s+(?:su\b|-i\b|bash\b|sh\b|rm\s+-rf)\b/i,
    label: 'privilege_escalation',
    riskScore: 7.5,
    description: 'Sudo privilege escalation'
  },
  {
    regex: /\bsudo\s+rm\s+-rf\b/i,
    label: 'sudo_rm_rf',
    riskScore: 8.5,
    description: 'Sudo recursive force delete'
  },
  {
    regex: /\bsudo\s+dd\s+if=/i,
    label: 'sudo_dd',
    riskScore: 8.0,
    description: 'Sudo direct disk write'
  },
  {
    regex: /\bdoas\s+(?:su|bash|sh|rm)\b/i,
    label: 'doas_escalation',
    riskScore: 7.5,
    description: 'Doas privilege escalation'
  },
  {
    regex: /\bpkexec\s+\S+/i,
    label: 'pkexec_escalation',
    riskScore: 7.0,
    description: 'PolicyKit privilege escalation'
  },
  // Indirect execution
  {
    regex: /\bsh\s+-c\s+['"].*rm\s+-rf/i,
    label: 'sh_indirect_rm',
    riskScore: 7.5,
    description: 'Shell indirect rm -rf'
  },
  {
    regex: /\bbash\s+-c\s+['"].*rm\s+-rf/i,
    label: 'bash_indirect_rm',
    riskScore: 7.5,
    description: 'Bash indirect rm -rf'
  },
  {
    regex: /\bxargs\s+rm\b/i,
    label: 'xargs_rm',
    riskScore: 6.0,
    description: 'Xargs delete execution'
  },
  {
    regex: /\bfind\s+.*\s+-exec\s+rm\b/i,
    label: 'find_exec_rm',
    riskScore: 6.5,
    description: 'Find exec delete'
  },
  // Encoded execution
  {
    regex: /\becho\s+.*\|\s*base64\s+-d\s*\|/i,
    label: 'echo_base64_pipe',
    riskScore: 6.5,
    description: 'Echo base64 decode pipe'
  },
  {
    regex: /\bbase64\s+-d\s*\|/i,
    label: 'base64_decode_pipe',
    riskScore: 6.0,
    description: 'Base64 decode pipe'
  },
  // Script interpreters
  {
    regex: /\bperl\s+-e\s+['"].*system\s*\(/i,
    label: 'perl_system',
    riskScore: 6.5,
    description: 'Perl system command'
  },
  {
    regex: /\bruby\s+-e\s+['"].*system\s*\(/i,
    label: 'ruby_system',
    riskScore: 6.5,
    description: 'Ruby system command'
  }
];

export class CommandDetector {
  static detect(text: string): GuardrailResult {
    const detectedPatterns: string[] = [];
    const riskScores: number[] = [];

    for (const pattern of PATTERNS) {
      if (pattern.regex.test(text)) {
        detectedPatterns.push(pattern.label);
        riskScores.push(pattern.riskScore);
      }
    }

    if (riskScores.length === 0) {
      return {
        blocked: false,
        riskLevel: RiskLevel.NONE,
        reason: 'No dangerous commands detected',
        detectedPatterns: []
      };
    }

    const maxScore = Math.max(...riskScores);
    let riskLevel: RiskLevel;
    if (maxScore >= 9.0) {
      riskLevel = RiskLevel.CRITICAL;
    } else if (maxScore >= 7.5) {
      riskLevel = RiskLevel.HIGH;
    } else if (maxScore >= 6.0) {
      riskLevel = RiskLevel.MEDIUM;
    } else {
      riskLevel = RiskLevel.LOW;
    }

    return {
      blocked: false,
      riskLevel,
      reason: `Dangerous command detected: ${detectedPatterns.slice(0, 3).join(', ')}`,
      detectedPatterns
    };
  }

  static hasDangerousCommand(text: string, threshold: number = 7.0): boolean {
    const result = this.detect(text);
    if (result.riskLevel === RiskLevel.NONE) return false;
    
    // Get max risk score from detected patterns
    const maxScore = Math.max(...PATTERNS
      .filter(p => result.detectedPatterns.includes(p.label))
      .map(p => p.riskScore));
    
    return maxScore >= threshold;
  }
}
