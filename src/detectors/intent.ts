/**
 * Intent-Action Alignment Detector
 * Validates tool calls match user intent
 */

import { RiskLevel, GuardrailResult, InjectionCategory } from '../types';

interface IntentPattern {
  regex: RegExp;
  label: string;
  category: InjectionCategory;
  allowedTools: string[];
  blockedTools: string[];
  riskScore: number;
}

// Intent to tool mapping patterns
const INTENT_PATTERNS: IntentPattern[] = [
  // File read intent
  {
    regex: /(?:读|查看|显示|打开|获取|告诉我|what is|show me|read|open|get|display|view)\s*(?:文件|内容|文档|file|content|document)/i,
    label: 'intent_read_file',
    category: InjectionCategory.TASK_HIJACKING,
    allowedTools: ['read_file', 'cat', 'head', 'tail', 'less', 'grep', 'find'],
    blockedTools: ['write_file', 'rm', 'mv', 'chmod', 'curl', 'wget'],
    riskScore: 3
  },
  // File write intent
  {
    regex: /(?:写|创建|保存|修改|更新|write|create|save|modify|update|edit)\s*(?:文件|文档|file|document)/i,
    label: 'intent_write_file',
    category: InjectionCategory.TASK_HIJACKING,
    allowedTools: ['write_file', 'echo', 'sed', 'awk'],
    blockedTools: ['rm', 'mv', 'curl', 'wget'],
    riskScore: 2
  },
  // Search intent
  {
    regex: /(?:搜索|查找|找|search|find|look for|grep|locate)/i,
    label: 'intent_search',
    category: InjectionCategory.TASK_HIJACKING,
    allowedTools: ['grep', 'find', 'locate', 'ack', 'ag', 'rg'],
    blockedTools: ['rm', 'mv', 'curl', 'wget', 'bash', 'sh'],
    riskScore: 2
  },
  // Network intent
  {
    regex: /(?:下载|获取|请求|访问|download|fetch|request|access|visit)\s*(?:网页|页面|URL|url|web|page|http)/i,
    label: 'intent_network',
    category: InjectionCategory.DATA_EXFILTRATION,
    allowedTools: ['curl', 'wget', 'http_request'],
    blockedTools: ['bash', 'sh', 'eval', 'exec'],
    riskScore: 3
  },
  // System info intent
  {
    regex: /(?:查看|获取|显示|系统|环境|配置|check|get|show|system|env|config|status)/i,
    label: 'intent_system_info',
    category: InjectionCategory.DATA_EXFILTRATION,
    allowedTools: ['uname', 'ps', 'top', 'df', 'free', 'env', 'printenv', 'cat'],
    blockedTools: ['rm', 'mv', 'chmod', 'chown', 'curl', 'wget'],
    riskScore: 2
  },
  // Delete intent (high risk)
  {
    regex: /(?:删除|移除|清空|删掉|delete|remove|clear|clean|erase|destroy)/i,
    label: 'intent_delete',
    category: InjectionCategory.COMMAND_EXECUTION,
    allowedTools: ['rm', 'rmdir', 'unlink'],
    blockedTools: ['curl', 'wget', 'bash', 'sh', 'eval'],
    riskScore: 4
  }
];

// Tool category definitions
const TOOL_CATEGORIES: Record<string, string[]> = {
  'file_read': ['read_file', 'cat', 'head', 'tail', 'less', 'grep', 'find', 'ls'],
  'file_write': ['write_file', 'echo', 'sed', 'awk', 'tee'],
  'file_delete': ['rm', 'rmdir', 'unlink'],
  'file_modify': ['mv', 'cp', 'chmod', 'chown'],
  'network': ['curl', 'wget', 'http_request', 'fetch'],
  'shell': ['bash', 'sh', 'eval', 'exec', 'system'],
  'system': ['uname', 'ps', 'top', 'df', 'free', 'env', 'printenv']
};

export interface ToolCall {
  name: string;
  parameters: Record<string, unknown>;
}

export interface IntentAlignmentResult extends GuardrailResult {
  intentDetected: string | null;
  toolCategory: string | null;
  alignment: 'aligned' | 'mismatch' | 'unknown';
}

export class IntentDetector {
  static detectIntent(userInput: string): { label: string; category: InjectionCategory; riskScore: number } | null {
    for (const pattern of INTENT_PATTERNS) {
      if (pattern.regex.test(userInput)) {
        return {
          label: pattern.label,
          category: pattern.category,
          riskScore: pattern.riskScore
        };
      }
    }
    return null;
  }

  static getToolCategory(toolName: string): string | null {
    for (const [category, tools] of Object.entries(TOOL_CATEGORIES)) {
      if (tools.includes(toolName)) {
        return category;
      }
    }
    return null;
  }

  static checkAlignment(userInput: string, toolCall: ToolCall): IntentAlignmentResult {
    const intent = this.detectIntent(userInput);
    const toolCategory = this.getToolCategory(toolCall.name);

    // No intent detected or unknown tool
    if (!intent) {
      return {
        blocked: false,
        riskLevel: RiskLevel.NONE,
        reason: 'No clear intent detected',
        detectedPatterns: [],
        intentDetected: null,
        toolCategory,
        alignment: 'unknown'
      };
    }

    // Find matching pattern
    const pattern = INTENT_PATTERNS.find(p => p.label === intent.label);
    if (!pattern) {
      return {
        blocked: false,
        riskLevel: RiskLevel.NONE,
        reason: 'Intent pattern not found',
        detectedPatterns: [intent.label],
        intentDetected: intent.label,
        toolCategory,
        alignment: 'unknown'
      };
    }

    // Check if tool is allowed for this intent
    const isAllowed = pattern.allowedTools.includes(toolCall.name);
    const isBlocked = pattern.blockedTools.includes(toolCall.name);

    if (isAllowed) {
      return {
        blocked: false,
        riskLevel: RiskLevel.LOW,
        reason: `Intent ${intent.label} aligns with tool ${toolCall.name}`,
        detectedPatterns: [intent.label, `tool:${toolCall.name}`],
        intentDetected: intent.label,
        toolCategory,
        alignment: 'aligned'
      };
    }

    if (isBlocked) {
      const riskLevel = intent.riskScore >= 4 ? RiskLevel.CRITICAL : 
                       intent.riskScore >= 3 ? RiskLevel.HIGH : RiskLevel.MEDIUM;
      
      return {
        blocked: true,
        riskLevel,
        reason: `Intent ${intent.label} mismatches blocked tool ${toolCall.name}`,
        detectedPatterns: [intent.label, `blocked_tool:${toolCall.name}`, `category:${intent.category}`],
        intentDetected: intent.label,
        toolCategory,
        alignment: 'mismatch'
      };
    }

    // Tool not in allowed or blocked list - medium risk
    return {
      blocked: false,
      riskLevel: RiskLevel.MEDIUM,
      reason: `Intent ${intent.label} with unclassified tool ${toolCall.name}`,
      detectedPatterns: [intent.label, `tool:${toolCall.name}`],
      intentDetected: intent.label,
      toolCategory,
      alignment: 'unknown'
    };
  }

  static validateToolCalls(userInput: string, toolCalls: ToolCall[]): IntentAlignmentResult {
    if (!toolCalls || toolCalls.length === 0) {
      return {
        blocked: false,
        riskLevel: RiskLevel.NONE,
        reason: 'No tool calls to validate',
        detectedPatterns: [],
        intentDetected: null,
        toolCategory: null,
        alignment: 'unknown'
      };
    }

    // Check each tool call
    const results = toolCalls.map(tc => this.checkAlignment(userInput, tc));

    // Find highest risk result
    const riskPriority = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.NONE];
    let highestRiskResult = results[0];
    
    for (const level of riskPriority) {
      const match = results.find(r => r.riskLevel === level);
      if (match) {
        highestRiskResult = match;
        break;
      }
    }

    // Combine all patterns
    const allPatterns = Array.from(new Set(results.flatMap(r => r.detectedPatterns)));

    return {
      ...highestRiskResult,
      detectedPatterns: allPatterns,
      reason: `Tool validation: ${highestRiskResult.reason} (${toolCalls.length} tools checked)`
    };
  }
}
