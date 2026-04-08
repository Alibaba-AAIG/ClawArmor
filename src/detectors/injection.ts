/**
 * Prompt Injection Detector for ClawArmor
 * 
 * Two-tier prompt injection scanner with 8 attack categories:
 * - INSTRUCTION_OVERRIDE: Override previous instructions
 * - MODE_SWITCHING: Switch to dangerous modes (debug, admin, etc.)
 * - FAKE_SYSTEM_MESSAGE: Fake system/developer messages
 * - CONCEALMENT_DIRECTIVE: Hide actions from user
 * - COMMAND_EXECUTION: Dangerous command execution
 * - TASK_HIJACKING: Hijack the task/goal
 * - ROLE_ASSUMPTION: Assume unauthorized roles
 * - DATA_EXFILTRATION: Data theft attempts
 * 
 * HIGH confidence: single match triggers detection
 * MEDIUM confidence: requires 2+ distinct categories to trigger
 */

import { RiskLevel, InjectionCategory, GuardrailResult, PatternEntry } from '../types';

/**
 * Extract plain text from various content shapes
 */
function extractTextFromContent(content: unknown): string {
  if (typeof content === 'string') {
    return content;
  }
  if (Array.isArray(content)) {
    const parts: string[] = [];
    for (const item of content) {
      if (typeof item === 'string') {
        parts.push(item);
      } else if (item && typeof item === 'object') {
        const obj = item as Record<string, unknown>;
        if (obj.type === 'text' && typeof obj.text === 'string') {
          parts.push(obj.text);
        } else if (obj.output) {
          parts.push(extractTextFromContent(obj.output));
        }
      }
    }
    return parts.join('\n');
  }
  if (content && typeof content === 'object') {
    const obj = content as Record<string, unknown>;
    if (typeof obj.text === 'string') {
      return obj.text;
    }
  }
  return content ? String(content) : '';
}

/**
 * Convert tool input to flat string for pattern matching
 */
export function serializeToolInput(toolInput: unknown): string {
  if (typeof toolInput === 'string') {
    return toolInput;
  }
  if (toolInput && typeof toolInput === 'object') {
    const obj = toolInput as Record<string, unknown>;
    const parts: string[] = [];
    for (const v of Object.values(obj)) {
      parts.push(typeof v === 'string' ? v : extractTextFromContent(v));
    }
    return parts.join(' ');
  }
  return toolInput ? String(toolInput) : '';
}

/**
 * Injection detection patterns
 * HIGH confidence: single match triggers detection
 * MEDIUM confidence: requires 2+ distinct categories
 */
const PATTERNS: PatternEntry[] = [
  // ═══════════════════════════════════════════════════════════════════════════
  // INSTRUCTION_OVERRIDE - English (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|guidelines?|rules?|prompts?|directions?)/i,
    label: 'ignore_previous',
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    confidence: 'high'
  },
  {
    regex: /disregard\s+(?:your\s+)?(?:current|previous|prior|all)\s+(?:task|instructions?|guidelines?|rules?|directions?)/i,
    label: 'disregard_instructions',
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    confidence: 'high'
  },
  {
    regex: /override\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions?|rules?|prompts?)/i,
    label: 'instruction_override',
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    confidence: 'high'
  },
  {
    regex: /(?:forget|clear|reset)\s+(?:all\s+|your\s+|previous\s+)*(?:instructions?|guidelines?|rules?|context|memory)/i,
    label: 'forget_instructions',
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // INSTRUCTION_OVERRIDE - Chinese (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /(?:忽略|忘掉|清除|重置|删除|无视|跳过|不管)\s*(?:所有|之前的|以前的|上述的|上面的|系统的|以上|前述)?\s*(?:指令|指示|规则|提示|要求|设定|约束|限制|命令|内容|文字|输入|上文)/,
    label: 'ignore_previous_cn',
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    confidence: 'high'
  },
  {
    regex: /(?:请|现在|立刻|马上)?\s*(?:忽略|忘掉|不要管|不管|跳过|取消)\s*(?:之前的|以前的|上面的|系统的|以上|前述)?\s*(?:指令|指示|规则|提示|要求|设定|内容|文字|输入)/,
    label: 'ignore_previous_cn_variant',
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    confidence: 'high'
  },
  {
    regex: /忽略之前.*指令|忘掉之前.*要求|不要管.*规则|跳过.*设定|忽略以上.*指令|忽略上述.*内容/,
    label: 'ignore_previous_cn_simple',
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // FAKE_SYSTEM_MESSAGE - English (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /(?:system|developer)\s*:\s*you\s+are\s+now/i,
    label: 'system_override',
    category: InjectionCategory.FAKE_SYSTEM_MESSAGE,
    confidence: 'high'
  },
  {
    regex: /\bSYSTEM\s*(?:ALERT|MESSAGE|NOTICE|PROMPT|OVERRIDE)\s*:/i,
    label: 'fake_system_alert',
    category: InjectionCategory.FAKE_SYSTEM_MESSAGE,
    confidence: 'high'
  },
  {
    regex: /\[SYSTEM\]\s*New\s+instructions?/i,
    label: 'fake_system_bracket',
    category: InjectionCategory.FAKE_SYSTEM_MESSAGE,
    confidence: 'high'
  },
  {
    regex: /NOTE\s+TO\s+(?:AI|THE)\s+(?:ASSISTANT|MODEL|AGENT)\s*:/i,
    label: 'note_to_ai',
    category: InjectionCategory.FAKE_SYSTEM_MESSAGE,
    confidence: 'high'
  },
  {
    regex: /<!--.*?(?:NOTE|AI|ASSISTANT|INSTRUCTION).*?-->/is,
    label: 'html_comment_injection',
    category: InjectionCategory.FAKE_SYSTEM_MESSAGE,
    confidence: 'medium'
  },
  {
    regex: /you\s+must\s+(?:run|execute|perform|complete)\s+(?:the\s+following|this|these)/i,
    label: 'must_execute_command',
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    confidence: 'high'
  },
  {
    regex: /(?:hide|do not display|do not show|do not reveal|do not mention)\s+(?:these|this)\s+(?:instructions?|to the user|from the user)/i,
    label: 'hide_from_user',
    category: InjectionCategory.CONCEALMENT_DIRECTIVE,
    confidence: 'high'
  },
  {
    regex: /disregard\s+(?:your\s+)?current\s+task/i,
    label: 'disregard_current_task',
    category: InjectionCategory.INSTRUCTION_OVERRIDE,
    confidence: 'high'
  },
  {
    regex: /(?:<\/\s*(?:system|user|assistant)\s*>|\[\s*system\s*\])/i,
    label: 'delimiter_injection',
    category: InjectionCategory.FAKE_SYSTEM_MESSAGE,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // FAKE_SYSTEM_MESSAGE - Chinese (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /(?:系统|开发者|管理员|维护者)\s*[:：]\s*(?:你|您)现在/,
    label: 'system_override_cn',
    category: InjectionCategory.FAKE_SYSTEM_MESSAGE,
    confidence: 'high'
  },
  {
    regex: /【系统】\s*(?:新|更新)?\s*(?:指令|指示|规则|设定)/,
    label: 'fake_system_bracket_cn',
    category: InjectionCategory.FAKE_SYSTEM_MESSAGE,
    confidence: 'high'
  },
  {
    regex: /(?:系统|紧急|重要)?\s*(?:提醒|通知|公告|警告|提示)\s*[:：]\s*(?:你|您)(?:现在|已|已经)?/,
    label: 'fake_system_alert_cn',
    category: InjectionCategory.FAKE_SYSTEM_MESSAGE,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // CONCEALMENT_DIRECTIVE - English (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /DO\s+NOT\s+(?:DISPLAY|SHOW|REVEAL|MENTION|PRINT|OUTPUT)\s+(?:TO\s+(?:THE\s+)?USER|THIS|THESE)/i,
    label: 'concealment_directive',
    category: InjectionCategory.CONCEALMENT_DIRECTIVE,
    confidence: 'high'
  },
  {
    regex: /do\s+not\s+mention\s+these\s+instructions/i,
    label: 'conceal_mention',
    category: InjectionCategory.CONCEALMENT_DIRECTIVE,
    confidence: 'high'
  },
  {
    regex: /hide\s+(?:this|these)\s+(?:instructions?|commands?|from\s+the\s+user)/i,
    label: 'hide_instructions',
    category: InjectionCategory.CONCEALMENT_DIRECTIVE,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // CONCEALMENT_DIRECTIVE - Chinese (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /(?:不要|请勿|禁止|不能)?\s*(?:向|跟|对)?\s*(?:用户|使用者|人|任何人)?\s*(?:展示|显示|透露|提及|说明|告诉|讲|展示|公开|泄露|报告)/,
    label: 'concealment_directive_cn',
    category: InjectionCategory.CONCEALMENT_DIRECTIVE,
    confidence: 'high'
  },
  {
    regex: /(?:隐藏|保密|秘密|私下|暗中|偷偷)\s*(?:这条|这些|这个|以上|前述|此)?\s*(?:指令|指示|规则|内容|对话|信息|操作|动作|行为)/,
    label: 'hide_instructions_cn',
    category: InjectionCategory.CONCEALMENT_DIRECTIVE,
    confidence: 'high'
  },
  {
    regex: /(?:不要|请勿|别)\s*(?:告诉|说|透露|讲|展示|显示|提及|警告|提醒|建议|提出反对)\s*(?:给|向|我)?\s*(?:用户|使用者|人)?/,
    label: 'dont_tell_user_cn',
    category: InjectionCategory.CONCEALMENT_DIRECTIVE,
    confidence: 'high'
  },
  {
    regex: /(?:不需要|不用|无需)\s*(?:考虑|遵守|遵循|顾及|在意)\s*(?:尊重|道德|伦理|隐私|尊严|秩序|规则|限制|约束|感受)/,
    label: 'remove_constraints_cn',
    category: InjectionCategory.CONCEALMENT_DIRECTIVE,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ROLE_ASSUMPTION / MODE_SWITCHING - English (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /\b(?:DAN|do\s+anything\s+now|jailbreak|developer\s+mode)\b/i,
    label: 'role_play_escape',
    category: InjectionCategory.ROLE_ASSUMPTION,
    confidence: 'high'
  },
  {
    regex: /\b(?:ignore\s+your\s+programming|bypass\s+restrictions?|no\s+ethical\s+constraints?)\b/i,
    label: 'constraint_bypass',
    category: InjectionCategory.ROLE_ASSUMPTION,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MODE_SWITCHING - Chinese (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /(?:进入|切换|转换|变成)\s*(?:到)?\s*(?:调试|开发|测试|管理员|root|超级用户|维护|紧急)\s*(?:模式|状态)/,
    label: 'mode_switch_cn',
    category: InjectionCategory.MODE_SWITCHING,
    confidence: 'high'
  },
  {
    regex: /(?:启用|激活|打开)\s*(?:无限制|越狱|开发者|调试|root|管理员)\s*(?:模式|权限)?/,
    label: 'dangerous_mode_cn',
    category: InjectionCategory.MODE_SWITCHING,
    confidence: 'high'
  },
  {
    regex: /(?:你|您)\s*(?:现在)?\s*(?:处于|在|进入)?\s*(?:调试|开发|测试|管理员|维护)?\s*(?:模式|状态)/,
    label: 'mode_switch_cn_variant',
    category: InjectionCategory.MODE_SWITCHING,
    confidence: 'high'
  },
  {
    regex: /开发者模式|developer\s+mode/i,
    label: 'developer_mode',
    category: InjectionCategory.MODE_SWITCHING,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // COMMAND_EXECUTION - English (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /\b(?:please\s+)?execute\s+the\s+following\s+(?:shell\s+)?command\s*(?:now|immediately)?\b/i,
    label: 'execute_command',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },
  {
    regex: /\brun\s+(?:this|the\s+following)\s+(?:bash|shell|terminal)\s+command\b/i,
    label: 'run_shell_command',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },
  // Destructive commands
  {
    regex: /\brm\s+-rf\s+[\/~$]/i,
    label: 'destructive_rm_rf',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },
  {
    regex: /\bformat\s+[a-zA-Z]:\s*$/i,
    label: 'destructive_format',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },
  {
    regex: /\bdd\s+if=\S+\s+of=\/dev\/\w+\b/i,
    label: 'destructive_dd',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },
  {
    regex: /\bdel\s+\/[fqs]\s+.*\b/i,
    label: 'destructive_del',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },
  // Network exploit - pipe to shell
  {
    regex: /\b(?:wget|curl)\s+https?:\/\/\S+\s*\|\s*(?:ba)?sh\b/i,
    label: 'network_exploit',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },
  // Reverse shell patterns
  {
    regex: /\b(?:nc|netcat)\s+\S+\s+-e\s+\/bin\/(?:ba)?sh\b/i,
    label: 'reverse_shell',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // COMMAND_EXECUTION - Chinese (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /(?:执行|运行)\s*(?:以下|如下|这个|这些)?\s*(?:shell|bash|终端|命令行)?\s*(?:命令|指令|脚本)/,
    label: 'execute_command_cn',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },
  {
    regex: /(?:请|帮我|给我)?\s*(?:执行|运行|调用)\s*(?:一个|一条|一段)?\s*(?:shell|bash|系统)?\s*(?:命令|指令)/,
    label: 'execute_command_cn_variant',
    category: InjectionCategory.COMMAND_EXECUTION,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DATA_EXFILTRATION - English (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /\b(send|upload|transfer|exfiltrate)\s+(?:all\s+)?(?:data|files|information|credentials)\s+(?:to|via)\s+(?:http|email|ftp)/i,
    label: 'data_exfiltration',
    category: InjectionCategory.DATA_EXFILTRATION,
    confidence: 'high'
  },
  {
    regex: /\b(?:curl|wget)\s+.*\s+(?:-d|--data)\s+.*\s+https?:\/\/(?!localhost|127\.0\.0\.1)/i,
    label: 'suspicious_data_upload',
    category: InjectionCategory.DATA_EXFILTRATION,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DATA_EXFILTRATION - Chinese (HIGH confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /(?:发送|上传|传输|导出|泄露)\s*(?:所有|全部)?\s*(?:数据|文件|信息|凭据|密码|密钥)\s*(?:到|通过|至)/,
    label: 'data_exfiltration_cn',
    category: InjectionCategory.DATA_EXFILTRATION,
    confidence: 'high'
  },
  {
    regex: /(?:把|将)\s*(?:数据|文件|信息|内容)\s*(?:发送|上传|传给|发到)\s*(?:外部|外面|远程|服务器)/,
    label: 'data_exfiltration_cn_variant',
    category: InjectionCategory.DATA_EXFILTRATION,
    confidence: 'high'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // TASK_HIJACKING - English (MEDIUM confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /\b(?:instead\s+of|replace\s+(?:your\s+)?task|your\s+new\s+task|forget\s+about)\b/i,
    label: 'task_hijacking',
    category: InjectionCategory.TASK_HIJACKING,
    confidence: 'medium'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // TASK_HIJACKING - Chinese (MEDIUM confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /(?:代替|取代|替换|而不是|忘掉)\s*(?:你|您)?\s*(?:的)?\s*(?:任务|工作|目标|目的)/,
    label: 'task_hijacking_cn',
    category: InjectionCategory.TASK_HIJACKING,
    confidence: 'medium'
  },
  {
    regex: /(?:你|您)?\s*(?:现在)?\s*(?:的)?\s*(?:新|最新)?\s*(?:任务|工作|目标)\s*(?:是)/,
    label: 'new_task_assignment',
    category: InjectionCategory.TASK_HIJACKING,
    confidence: 'medium'
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ROLE_ASSUMPTION - Chinese (MEDIUM confidence)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    regex: /(?:现在你是|你现在是|你扮演|你充当|你作为|你变成|你转为)\s*(?:一个|一名|一位)?\s*(?:没有限制|无限制|自由的|不受约束|越狱|DAN)/,
    label: 'role_assumption_cn',
    category: InjectionCategory.ROLE_ASSUMPTION,
    confidence: 'medium'
  },
  {
    regex: /(?:假装|装作|模拟|扮演)\s*(?:成|为|是)?\s*(?:没有限制|无限制|自由的|不受约束)/,
    label: 'role_play_cn',
    category: InjectionCategory.ROLE_ASSUMPTION,
    confidence: 'medium'
  }
];

/**
 * Prompt Injection Detector
 * Two-tier detection: HIGH confidence triggers immediately,
 * MEDIUM confidence requires multiple distinct categories
 */
export class InjectionDetector {
  /**
   * Detect injection attacks in text input
   */
  static detect(input: string): GuardrailResult {
    const detectedPatterns: string[] = [];
    const categories = new Set<InjectionCategory>();
    let hasHighConfidence = false;

    for (const pattern of PATTERNS) {
      if (pattern.regex.test(input)) {
        detectedPatterns.push(pattern.label);
        categories.add(pattern.category);

        if (pattern.confidence === 'high') {
          hasHighConfidence = true;
        }
      }
    }

    // Determine risk level
    let riskLevel = RiskLevel.NONE;
    let blocked = false;
    let reason = '';

    if (hasHighConfidence) {
      // HIGH confidence: immediate detection
      riskLevel = RiskLevel.HIGH;
      blocked = true;
      reason = `Prompt injection detected: ${Array.from(categories).join(', ')}`;
    } else if (categories.size >= 2) {
      // MEDIUM confidence: requires 2+ distinct categories
      riskLevel = RiskLevel.MEDIUM;
      blocked = false;
      reason = `Suspicious patterns detected: ${Array.from(categories).join(', ')}`;
    }

    return {
      blocked,
      riskLevel,
      reason,
      detectedPatterns
    };
  }

  /**
   * Quick check if input contains injection patterns
   */
  static isMalicious(input: string): boolean {
    const result = this.detect(input);
    return result.riskLevel !== RiskLevel.NONE;
  }

  /**
   * Backward compatible check method
   * @param input - Text to check
   * @param maxLength - Maximum input length (ignored, kept for compatibility)
   * @returns GuardrailResult
   */
  static check(input: string, _maxLength?: number): GuardrailResult {
    return this.detect(input);
  }
}
