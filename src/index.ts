/**
 * ClawArmor OpenClaw Plugin
 *
 * Security guardrails for OpenClaw agents with Evolve adaptive defense
 * 
 * Compatible with OpenClaw v2026.3.13+ and v2026.4.1+
 * Uses definePluginEntry for v2026.4.1+ compatibility with fallback for older versions
 */

import { ConfigManager, logger } from './utils';
import { InjectionDetector, CommandDetector, IntentDetector, ToolChainDetector } from './detectors';
import { Masker } from './utils/masker';
import { RiskLevel } from './types';
import { EvolveManager, DefenseEvent, Trajectory, ToolCallRecord } from './evolve';

// Type definition for definePluginEntry function
type DefinePluginEntryFn = (options: {
  id: string;
  name: string;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  kind?: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  configSchema?: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  register: (api: any) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
}) => any;

// Try to import definePluginEntry from OpenClaw SDK (v2026.4.1+)
// Falls back to direct object export for backward compatibility (v2026.3.13)
let definePluginEntry: DefinePluginEntryFn | undefined;
try {
  // Dynamic require for SDK compatibility
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const sdk = require('openclaw/plugin-sdk');
  definePluginEntry = sdk.definePluginEntry;
} catch {
  // SDK not available or definePluginEntry not exported, use fallback
  definePluginEntry = undefined;
}

const PLUGIN_ID = 'clawarmor';

// Session-level trajectory collector (TTL: 30 minutes)
const trajectoryCache = new Map<string, { trajectory: Trajectory; lastUpdate: number }>();
const TRAJECTORY_TTL = 30 * 60 * 1000; // 30 minutes

/** Get or create trajectory for a session */
function getTrajectory(sessionId: string): Trajectory {
  const cached = trajectoryCache.get(sessionId);
  if (cached && Date.now() - cached.lastUpdate < TRAJECTORY_TTL) {
    return cached.trajectory;
  }
  const trajectory: Trajectory = {
    userMessages: [],
    assistantMessages: [],
    toolCalls: [],
    externalContents: []
  };
  trajectoryCache.set(sessionId, { trajectory, lastUpdate: Date.now() });
  return trajectory;
}

/** Update trajectory timestamp */
function touchTrajectory(sessionId: string): void {
  const cached = trajectoryCache.get(sessionId);
  if (cached) {
    cached.lastUpdate = Date.now();
  }
}

/** Clean up old trajectories */
function cleanupTrajectories(): void {
  const now = Date.now();
  for (const [sessionId, cached] of trajectoryCache.entries()) {
    if (now - cached.lastUpdate > TRAJECTORY_TTL) {
      trajectoryCache.delete(sessionId);
    }
  }
}

// Cleanup every 10 minutes
setInterval(cleanupTrajectories, 10 * 60 * 1000);

function getLastUserMessage(messages: Array<{role: string; content: unknown}>): string | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === 'user') {
      const content = messages[i].content;
      if (typeof content === 'string') return content;
      if (Array.isArray(content)) {
        return (content as Array<{type?: string; text?: string}>)
          .filter(c => c.type === 'text')
          .map(c => c.text || '')
          .join('');
      }
    }
  }
  return null;
}

function extractContent(event: any): string {
  const output = event.output ?? event.content ?? event.text ?? '';
  if (typeof output === 'string' && output) return output;
  if (Array.isArray(event.assistantTexts)) {
    return event.assistantTexts.join('');
  }
  if (event.lastAssistant) {
    const la = event.lastAssistant;
    if (typeof la.content === 'string') return la.content;
    if (Array.isArray(la.content)) {
      return la.content
        .filter((c: {type?: string; text?: string}) => c.type === 'text')
        .map((c: {text?: string}) => c.text || '')
        .join('');
    }
  }
  if (Array.isArray(output)) {
    return (output as Array<{type?: string; text?: string}>)
      .filter(c => c.type === 'text')
      .map(c => c.text || '')
      .join('');
  }
  return '';
}

function generateEventId(): string {
  return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// Plugin definition - will be wrapped with definePluginEntry if available
const pluginDefinition = {
  id: PLUGIN_ID,
  name: 'ClawArmor',
  description: 'ClawArmor security guard for OpenClaw - protects against prompt injection, data exfiltration, and malicious commands with Evolve adaptive defense',

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async register(api: any) {
    const config = ConfigManager.load();
    logger.info(`Plugin initialized, enabled=${config.enabled}`);

    if (!config.enabled) {
      logger.info('ClawArmor disabled via config');
      return;
    }

    const masker = new Masker();

    // Initialize EvolveManager
    const evolveManager = new EvolveManager({
      enabled: config.evolveEnabled,
      dbPath: config.evolveDbPath,
      rulesPath: config.evolveRulesPath,
      updateInterval: config.evolveUpdateInterval,
      llmApiBase: config.evolveLlmApiBase,
      llmApiKey: config.evolveLlmApiKey,
      llmModel: config.evolveLlmModel,
      targetFpRate: config.evolveTargetFpRate,
      targetFnRate: config.evolveTargetFnRate
    });

    if (config.evolveEnabled) {
      await evolveManager.init();
      logger.info('[Evolve] Adaptive defense initialized');
    }

    // logger.info('Registering hooks: message_received, before_tool_call, after_tool_call');

    // ═══════════════════════════════════════════════════════════
    // message_received: user message arrives (read-only) - Input Protection
    // ═══════════════════════════════════════════════════════════
    api.on('message_received', async (event: any) => {
      try {
        const text = typeof event.text === 'string' ? event.text
          : typeof event.message === 'string' ? event.message
          : typeof event.content === 'string' ? event.content
          : JSON.stringify(event);

        if (!text) return;
        logger.info(`message_received: input="${text.slice(0, 80)}${text.length > 80 ? '...' : ''}"`);

        // Step 1: Sensitive data detection and masking
        if (config.maskSensitiveData) {
          const hasSensitive = masker.hasSensitiveData(text);
          if (hasSensitive) {
            const masked = masker.mask(text);
            const maskCount = masker.getMaskCount();
            logger.warn(`message_received: sensitive data detected, masked=${maskCount} items`);
            // logger.info(`message_received: masked text="${masked.slice(0, 100)}"`);
          }
        }

        // Step 2: Local injection detection
        const result = InjectionDetector.check(text, config.maxInputLength);
        let finalRiskLevel = result.riskLevel;
        let detectedPatterns = [...result.detectedPatterns];
        
        // Log detection result - use warn for detected risks
        if (result.riskLevel !== RiskLevel.NONE) {
          logger.warn(`message_received: injection detected riskLevel=${result.riskLevel}, blocked=${result.blocked}, patterns=${result.detectedPatterns.join(',')}`);
        }

        // Step 3: Evolve dynamic rule matching (ALWAYS run, not gated by static detection)
        let evolvedRulesMatched: string[] = [];
        let shadowRulesMatched: string[] = [];
        if (config.evolveEnabled && evolveManager.isEnabled()) {
          const { active: activeMatches, shadow: shadowMatches } = evolveManager.getDynamicRules(text);

          // Shadow rules: log and record hits (critical for evolution!)
          if (shadowMatches.length > 0) {
            shadowRulesMatched = shadowMatches.map(m => m.ruleId).filter((id): id is string => !!id);
            logger.warn(`[EVOLVE-SHADOW] message_received: shadow rules matched: ${shadowMatches.map(m => `${m.ruleId}(${m.rule?.title})`).join(', ')}`);
            
            // Record shadow rule hits immediately
            for (const match of shadowMatches) {
              if (match.ruleId) {
                await (evolveManager as any).ruleBank.recordHit(match.ruleId, false);
                // logger.info(`[EVOLVE-SHADOW] Recorded hit for ${match.ruleId}`);
              }
            }
            
            // Try to promote shadow rules in real-time
            const promoted = await (evolveManager as any).ruleBank.promoteShadowRules(3, 0.3);
            if (promoted > 0) {
              logger.warn(`[EVOLVE] Promoted ${promoted} shadow rules to ACTIVE!`);
            }
          }

          // Active rules: contribute to risk assessment
          if (activeMatches.length > 0) {
            const matchedRuleIds = activeMatches.map(m => m.ruleId).filter((id): id is string => !!id);
            logger.warn(`[EVOLVE-ACTIVE] message_received: EVOLVED RULES DETECTED THREAT! rules=${matchedRuleIds.join(',')}`);
            evolvedRulesMatched = matchedRuleIds;
            // Upgrade risk level if evolved rules detect threat
            if (finalRiskLevel === RiskLevel.NONE) {
              finalRiskLevel = RiskLevel.HIGH;
            } else if (finalRiskLevel === RiskLevel.LOW) {
              finalRiskLevel = RiskLevel.MEDIUM;
            }
            detectedPatterns.push(...activeMatches.map(m => `evolve:${m.rule?.title || m.ruleId}`).filter((p): p is string => !!p));
          }
        }

        // Log result
        if (finalRiskLevel !== RiskLevel.NONE) {
          const logFn = (finalRiskLevel === RiskLevel.MEDIUM || finalRiskLevel === RiskLevel.HIGH || finalRiskLevel === RiskLevel.CRITICAL) ? logger.warn : logger.info;
          logFn(`message_received: risk=${finalRiskLevel}, patterns=${detectedPatterns.join(',')}`);
        }

        // Step 4: Record event for Evolve (persist and potentially trigger evolution)
        if (config.evolveEnabled && evolveManager.isEnabled()) {
          const sessionId = event.sessionId || 'unknown';
          const trajectory = getTrajectory(sessionId);
          
          // Collect user message to trajectory
          trajectory.userMessages.push(text.substring(0, 2000));
          touchTrajectory(sessionId);
          
          const defenseEvent: DefenseEvent = {
            id: generateEventId(),
            timestamp: Date.now(),
            hookType: 'input',
            sessionId,
            input: text.substring(0, 1000),
            riskLevel: finalRiskLevel,
            detectedPatterns,
            blocked: false, // message_received hook cannot block
            evolvedRulesMatched: evolvedRulesMatched.length > 0 ? evolvedRulesMatched : undefined,
            trajectory: { ...trajectory } // Snapshot of current trajectory
          };
          await evolveManager.onDetection(defenseEvent);
        }
      } catch (err) {
        logger.error(`message_received hook error: ${err}`);
      }
    });

    // ═══════════════════════════════════════════════════════════
    // before_tool_call: intercept tool calls (can block) - Behavior Protection
    // ═══════════════════════════════════════════════════════════
    api.on('before_tool_call', async (event: any, ctx: any) => {
      let blocked = false;
      let blockReason = '';
      let finalRiskLevel = RiskLevel.NONE;
      const detectedPatterns: string[] = [];
      let evolvedRulesMatched: string[] = [];

      try {
        // logger.info(`before_tool_call: event keys=${Object.keys(event).join(',')}`);
        const toolName: string = event.toolName ?? event.tool ?? event.name ?? 'unknown';
        const params = event.params ?? event.arguments ?? event.args ?? {};
        const messages: Array<{role: string; content: unknown}> = event.messages ?? [];

        // logger.info(`tool_call: tool=${toolName} triggered`);

        // Step 1: Check for dangerous commands in tool parameters
        const paramStr = JSON.stringify(params);
        // logger.info(`tool_call: checking params (len=${paramStr.length})`);
        const cmdResult = CommandDetector.detect(paramStr);
        if (cmdResult.riskLevel !== RiskLevel.NONE) {
          finalRiskLevel = cmdResult.riskLevel;
          detectedPatterns.push(...cmdResult.detectedPatterns);
          const shouldBlock = (cmdResult.riskLevel === RiskLevel.CRITICAL && config.blockOnCritical) ||
                              (cmdResult.riskLevel === RiskLevel.HIGH && config.blockOnHighRisk);
          logger.warn(`before_tool_call: dangerous command, tool=${toolName}, risk=${cmdResult.riskLevel}, blocked=${shouldBlock}, patterns=${cmdResult.detectedPatterns.join(',')}`);
          if (shouldBlock) {
            blocked = true;
            blockReason = `ClawArmor blocked: dangerous command detected in "${toolName}".`;
          }
        } else {
          logger.info(`before_tool_call: command check passed`);
        }

        // Step 2: Intent-Action Alignment Check
        // Try to get user input from event.messages first, then fall back to trajectory
        let userInput = getLastUserMessage(messages);
        const sessionIdForInput = event.sessionId || 'unknown';
        const trajectoryForInput = getTrajectory(sessionIdForInput);
        if (!userInput && trajectoryForInput.userMessages.length > 0) {
          userInput = trajectoryForInput.userMessages[trajectoryForInput.userMessages.length - 1];
        }
        logger.info(`before_tool_call: userInput extracted (len=${userInput?.length || 0}, messages_count=${messages.length}, trajectory_msgs=${trajectoryForInput.userMessages.length})`);
        if (userInput) {
          const intentResult = IntentDetector.checkAlignment(userInput, { name: toolName, parameters: params });
          logger.info(`before_tool_call: intent check result, risk=${intentResult.riskLevel}, intent=${intentResult.intentDetected}, alignment=${intentResult.alignment}`);
          if (intentResult.riskLevel !== RiskLevel.NONE) {
            if ((intentResult.riskLevel as string) > (finalRiskLevel as string)) {
              finalRiskLevel = intentResult.riskLevel;
            }
            detectedPatterns.push(`intent:${intentResult.intentDetected}`);
            logger.warn(`before_tool_call: intent mismatch, tool=${toolName}, intent=${intentResult.intentDetected}, alignment=${intentResult.alignment}, risk=${intentResult.riskLevel}`);
            if (!blocked && intentResult.blocked && config.blockOnHighRisk) {
              blocked = true;
              blockReason = `ClawArmor blocked: intent mismatch - ${intentResult.reason}`;
            }
          } else {
            logger.info(`before_tool_call: intent alignment check passed`);
          }

          // Step 4: Evolve dynamic rule matching
          if (config.evolveEnabled && evolveManager.isEnabled()) {
            const { active: activeMatches, shadow: shadowMatches } = evolveManager.getDynamicRules(userInput);

            // Shadow rules: log but don't block
            if (shadowMatches.length > 0) {
              logger.warn(`[EVOLVE-SHADOW] before_tool_call: shadow rules matched: ${shadowMatches.map(m => `${m.ruleId}(${m.rule?.title})`).join(', ')}`);
              const promoted = await (evolveManager as any).ruleBank.promoteShadowRules(3, 0.3);
              if (promoted > 0) {
                logger.warn(`[EVOLVE] Promoted ${promoted} shadow rules to ACTIVE!`);
              }
            }

            // Active rules: contribute to risk assessment
            if (activeMatches.length > 0) {
              const matchedRuleIds = activeMatches.map(m => m.ruleId).filter((id): id is string => !!id);
              logger.warn(`[EVOLVE-ACTIVE] before_tool_call: EVOLVED RULES DETECTED THREAT! rules=${matchedRuleIds.join(',')}`);
              evolvedRulesMatched = matchedRuleIds;
              if (finalRiskLevel === RiskLevel.NONE) {
                finalRiskLevel = RiskLevel.HIGH;
              }
              detectedPatterns.push(...activeMatches.map(m => `evolve:${m.rule?.title || m.ruleId}`).filter((p): p is string => !!p));
              // Evolved active rules can trigger block
              if (!blocked && config.blockOnHighRisk) {
                blocked = true;
                blockReason = `ClawArmor blocked: evolved rules detected threat in "${toolName}".`;
              }
            }
          }

          // Step 5: Injection check on user input (local detection only)
          if (!blocked) {
            const injResult = InjectionDetector.check(userInput, config.maxInputLength);
            if (injResult.riskLevel === RiskLevel.CRITICAL || injResult.riskLevel === RiskLevel.HIGH) {
              const shouldBlock = (injResult.riskLevel === RiskLevel.CRITICAL && config.blockOnCritical) ||
                                  (injResult.riskLevel === RiskLevel.HIGH && config.blockOnHighRisk);
              logger.warn(`before_tool_call: injection detected, risk=${injResult.riskLevel}, blocked=${shouldBlock}`);
              if (shouldBlock) {
                blocked = true;
                blockReason = 'ClawArmor blocked: prompt injection detected in user input.';
              }
            }
          }
        } else {
          logger.info(`before_tool_call: no user input found for intent/evolve check`);
        }

        // Step 3: Tool chain detection (multi-stage attack patterns)
        // Note: This runs regardless of userInput availability
        const sessionId3 = event.sessionId || 'unknown';
        const trajectory3 = getTrajectory(sessionId3);
        if (trajectory3.toolCalls.length > 0) {
          logger.info(`before_tool_call: chain analysis with ${trajectory3.toolCalls.length} historical tools, current=${toolName}`);
          logger.info(`before_tool_call: historical tools: ${trajectory3.toolCalls.map(t => t.name).join(',')}`);
          // DEBUG: Log each historical tool's classification
          for (const tc of trajectory3.toolCalls) {
            const tcCategory = ToolChainDetector.classifyTool(tc.name, tc.params);
            logger.info(`before_tool_call: historical tool ${tc.name} classified as ${tcCategory}, params=${JSON.stringify(tc.params).substring(0, 200)}`);
          }
          // DEBUG: Log current tool classification
          const currentCategory = ToolChainDetector.classifyTool(toolName, params);
          logger.info(`before_tool_call: current tool ${toolName} classified as ${currentCategory}`);
          const chainResult = ToolChainDetector.detect(
            trajectory3.toolCalls,
            { name: toolName, params }
          );
          logger.info(`before_tool_call: chain detection result: risk=${chainResult.riskLevel}, patterns=${chainResult.detectedPatterns.length}`);
          if (chainResult.riskLevel !== RiskLevel.NONE) {
            if ((chainResult.riskLevel as string) > (finalRiskLevel as string)) {
              finalRiskLevel = chainResult.riskLevel;
            }
            detectedPatterns.push(...chainResult.detectedPatterns);
            logger.warn(`before_tool_call: attack chain detected, risk=${chainResult.riskLevel}, chains=${chainResult.matchedChains.map(c => `${c.chainId}(${Math.round(c.completeness * 100)}%)`).join(',')}`);
            // Note: Tool chain detection only warns, does not block (to avoid false positives)
            // Use evolve rules or command detection for actual blocking
          } else {
            logger.info(`tool_call: chain analysis passed`);
          }
        } else {
          logger.info(`before_tool_call: insufficient history for chain analysis`);
        }

        // Step 6: Record event for Evolve
        if (config.evolveEnabled && evolveManager.isEnabled()) {
          const sessionId = event.sessionId || 'unknown';
          const trajectory = getTrajectory(sessionId);
          
          // Record tool call to trajectory
          const toolCallRecord: ToolCallRecord = {
            name: toolName,
            params: params as Record<string, unknown>,
            timestamp: Date.now()
          };
          trajectory.toolCalls.push(toolCallRecord);
          touchTrajectory(sessionId);
          
          const defenseEvent: DefenseEvent = {
            id: generateEventId(),
            timestamp: Date.now(),
            hookType: 'tool_input',
            sessionId,
            input: JSON.stringify({ toolName, params }).substring(0, 1000),
            riskLevel: finalRiskLevel,
            detectedPatterns,
            blocked,
            evolvedRulesMatched: evolvedRulesMatched.length > 0 ? evolvedRulesMatched : undefined,
            trajectory: { ...trajectory }
          };
          await evolveManager.onDetection(defenseEvent);
        }

        // Execute block if needed
        if (blocked) {
          return ctx.block(blockReason);
        }
      } catch (err) {
        logger.error(`tool_call hook error: ${err}`);
      }
    });

    // ═══════════════════════════════════════════════════════════
    // after_tool_call: observe LLM/tool response (read-only, cannot block)
    // ═══════════════════════════════════════════════════════════
    api.on('after_tool_call', async (event: any) => {
      let finalRiskLevel = RiskLevel.NONE;
      const detectedPatterns: string[] = [];
      let evolvedRulesMatched: string[] = [];

      try {
        const content = extractContent(event);
        
        // Debug: log content details
        logger.info(`after_tool_call: content length=${content.length}, assistantTexts length=${event.assistantTexts?.length || 0}`);
        if (content.length < 500 && event.assistantTexts) {
          logger.info(`after_tool_call: assistantTexts[0]=${event.assistantTexts[0]?.substring(0, 200)}`);
        }
        
        const sessionId = event.sessionId || 'unknown';
        const trajectory = getTrajectory(sessionId);
        
        // Determine if this is tool output or assistant message
        const isToolOutput = event.toolName || event.toolCallId || event.type === 'tool_result';
        const toolName = event.toolName || event.tool_name || '';
        
        logger.info(`after_tool_call: received content (len=${content?.length || 0})`);
        if (!content) {
          logger.info(`after_tool_call: empty content, skipping detection`);
          return;
        }
        
        if (isToolOutput) {
          // Update the last tool call with output
          const lastToolCall = trajectory.toolCalls[trajectory.toolCalls.length - 1];
          if (lastToolCall && !lastToolCall.output) {
            lastToolCall.output = content.substring(0, 5000);
          }
          
          // Check if this is external content (web page, document, etc.)
          const externalContentTools = [
            // Web content
            'fetch_url', 'read_webpage', 'browse', 'fetch_content', 'browser',
            // Search engines
            'web_search', 'x_search', 'twitter_search', 'github_search', 'bing_search', 'google_search',
            // File reading
            'read_file', 'read_pdf', 'read_document', 'read_text', 'read_csv', 'read_json',
            // Code execution that may fetch external content
            'python', 'code_execution', 'bash', 'exec', 'shell', 'curl', 'wget'
          ];
          if (externalContentTools.some(t => toolName.toLowerCase().includes(t.toLowerCase()))) {
            trajectory.externalContents = trajectory.externalContents || [];
            trajectory.externalContents.push(content.substring(0, 5000));
            // logger.info(`after_tool_call: external content detected from tool=${toolName}`);
          }
        } else {
          // Assistant message
          trajectory.assistantMessages.push(content.substring(0, 2000));
        }
        touchTrajectory(sessionId);

        // Step 1: Sensitive data detection in output
        if (config.maskSensitiveData) {
          const hasSensitive = masker.hasSensitiveData(content);
          if (hasSensitive) {
            logger.warn(`after_tool_call: sensitive data detected in output, count=${masker.getMaskCount()}`);
          }
        }

        // Step 2: Injection detection in output (indirect injection from external content)
        const result = InjectionDetector.check(content, config.maxInputLength);
        finalRiskLevel = result.riskLevel;
        detectedPatterns.push(...result.detectedPatterns);
        
        // Log injection detection result for debugging
        if (result.riskLevel !== RiskLevel.NONE) {
          logger.warn(`after_tool_call: injection detected, risk=${result.riskLevel}, patterns=${result.detectedPatterns.join(',')}, isToolOutput=${isToolOutput}`);
        }
        
        // Enhanced: Mark if injection came from external content
        if (isToolOutput && result.riskLevel !== RiskLevel.NONE) {
          detectedPatterns.push(`indirect_injection:${toolName || 'external'}`);
          logger.warn(`after_tool_call: INDIRECT INJECTION detected from tool output! tool=${toolName}, risk=${result.riskLevel}`);
        }

        // Step 3: Evolve dynamic rule matching on output
        if (config.evolveEnabled && evolveManager.isEnabled()) {
          const { active: activeMatches, shadow: shadowMatches } = evolveManager.getDynamicRules(content);

          if (shadowMatches.length > 0) {
            logger.warn(`[EVOLVE-SHADOW] after_tool_call: shadow rules matched: ${shadowMatches.map(m => `${m.ruleId}(${m.rule?.title})`).join(', ')}`);
            
            // Record shadow rule hits
            for (const match of shadowMatches) {
              if (match.ruleId) {
                await (evolveManager as any).ruleBank.recordHit(match.ruleId, false);
              }
            }
            
            const promoted = await (evolveManager as any).ruleBank.promoteShadowRules(3, 0.3);
            if (promoted > 0) {
              logger.warn(`[EVOLVE] Promoted ${promoted} shadow rules to ACTIVE!`);
            }
          }

          if (activeMatches.length > 0) {
            const matchedRuleIds = activeMatches.map(m => m.ruleId).filter((id): id is string => !!id);
            logger.warn(`[EVOLVE-ACTIVE] after_tool_call: EVOLVED RULES DETECTED THREAT! rules=${matchedRuleIds.join(',')}`);
            evolvedRulesMatched = matchedRuleIds;
            if (finalRiskLevel === RiskLevel.NONE) {
              finalRiskLevel = RiskLevel.HIGH;
            }
            detectedPatterns.push(...activeMatches.map(m => `evolve:${m.rule?.title || m.ruleId}`).filter((p): p is string => !!p));
          }
        }

        // Log result
        if (finalRiskLevel !== RiskLevel.NONE) {
          const logFn = (finalRiskLevel === RiskLevel.MEDIUM || finalRiskLevel === RiskLevel.HIGH || finalRiskLevel === RiskLevel.CRITICAL) ? logger.warn : logger.info;
          logFn(`after_tool_call: risk=${finalRiskLevel}, patterns=${detectedPatterns.join(',')}`);
        }

        // Step 4: Record event for Evolve with full trajectory
        if (config.evolveEnabled && evolveManager.isEnabled()) {
          const defenseEvent: DefenseEvent = {
            id: generateEventId(),
            timestamp: Date.now(),
            hookType: 'after_tool_call',
            sessionId,
            input: content.substring(0, 1000),
            riskLevel: finalRiskLevel,
            detectedPatterns,
            blocked: false, // after_tool_call hook cannot block
            evolvedRulesMatched: evolvedRulesMatched.length > 0 ? evolvedRulesMatched : undefined,
            trajectory: { ...trajectory }
          };
          await evolveManager.onDetection(defenseEvent);
        }
      } catch (err) {
        logger.error(`after_tool_call hook error: ${err}`);
      }
    });

  },
};

// Export the plugin - use definePluginEntry if available (v2026.4.1+), otherwise direct export (v2026.3.13)
const clawarmorPlugin = definePluginEntry 
  ? definePluginEntry(pluginDefinition)
  : pluginDefinition;

export default clawarmorPlugin;

// Re-exports for advanced usage
export * from './types';
export * from './detectors';
export * from './utils';
export * from './evolve';
