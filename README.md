# ClawArmor

> **Self-Evolving Defense for AI Agents** — Protect against prompt injection, data exfiltration, and multi-stage attacks with adaptive security that learns and improves over time.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](package.json)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-v2026.4.1+-orange.svg)](https://openclaw.dev)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)

---

## Highlights / Why ClawArmor

- **Solves the False Positive Problem** — Different scenarios requiring different defense strategies. Static rules cause excessive false positives/negatives, ruining user experience. ClawArmor learns normal/attack patterns from each business context and automatically generates targeted rules.
- **Zero-Touch Continuous Security Improvement** — Automatically learns from failures, identifies defense gaps, and generates new detection rules without human intervention. The system gets smarter over time.
- **Multi-Layer Protection** — Three core detection points (input, behavior, output) providing comprehensive coverage across the AI Agent lifecycle.
- **Tool Chain Attack Detection** — Identifies multi-stage attacks spanning multiple tool calls (e.g., recon → credential read → exfiltration).
- **Shadow → Active Rule Lifecycle** — New rules start in shadow mode (monitoring only), graduate to active after validation, and get deprecated if ineffective.
- **Real-time Dashboard** — Web-based monitoring dashboard at `http://127.0.0.1:18790` for live threat visibility.

---

## Demo

| Demo | Description | Video |
|------|-------------|-------|
| Direct Injection | Detecting direct prompt injection attacks in real-time | [▶ Watch Demo]() |
| Indirect Injection | Detecting injection attacks hidden in tool responses | [▶ Watch Demo]() |
| Attack Chain | Full attack chain detection across tool calls | [▶ Watch Demo]() |
| Rule Evolution | Shadow rules promoting to Active after validation | [▶ Watch Demo]() |
| Self-Evolution | ClawArmor self-upgrade and defense evolution | [▶ Watch Demo]() |

---

## Architecture Overview

ClawArmor implements a **defense-in-depth + adaptive evolution** architecture, intercepting AI Agent interactions at **three critical hook points** and continuously evolving defense rules through its Evolution Engine.

![ClawArmor System Architecture](./docs/images/architecture.png)


The system consists of two layers. The upper **Three-Layer Defense Pipeline** processes user input through:
- **User Threat Protection** (Hook: `message_received`) — read-only detection of prompt injection and sensitive data
- **Behavior Protection** (Hook: `before_tool_call`) — risk alerts with optional blocking for dangerous commands
- **External Content Protection** (Hook: `after_tool_call`) — read-only scanning for indirect injection

The lower **Evolve Self-Defense Core** manages the rule lifecycle through Shadow, Active, and Deprecated stages, with adaptive threshold control and feedback learning to continuously optimize defense strategies.

### Rule Lifecycle

New rules start in **Shadow mode** (monitoring only), graduate to **Active** after validation (hits ≥ 3 & FP rate ≤ 30%), and get deprecated if ineffective (effectiveness < 0.2).

---

## Quick Start

### Prerequisites

- **Node.js** >= 18.0.0
- **OpenClaw** >= v2026.4.1 (for plugin system compatibility)
- **LLM API Key** (optional but recommended for self-evolution)

### Installation

```bash
# Clone the repository
git clone https://github.com/clawarmor/clawarmor-evolve.git
cd clawarmor-evolve/ClawArmor-OpenClaw-Plugin

# Install dependencies
npm install

# Build and install plugin
npm run install-plugin
```

### Configuration

Create the configuration file:

```bash
mkdir -p ~/.openclaw/clawarmor
cat > ~/.openclaw/clawarmor/config.json << 'EOF'
{
  "enabled": true,
  "blockOnCritical": true,
  "blockOnHighRisk": false,
  "maskSensitiveData": true,
  "evolveEnabled": true,
  "evolveLlmApiBase": "https://api.openai.com/v1",
  "evolveLlmApiKey": "sk-your-api-key-here",
  "evolveLlmModel": "gpt-4",
  "evolveUpdateInterval": 5,
  "evolveTargetFpRate": 0.05,
  "evolveTargetFnRate": 0.02
}
EOF
chmod 600 ~/.openclaw/clawarmor/config.json
```

### Start

```bash
# Start the OpenClaw gateway (ClawArmor loads automatically)
openclaw gateway start

# Or start dashboard for monitoring
npm run dashboard
# Dashboard available at http://127.0.0.1:18790
```

### Verify Installation

```bash
# Check ClawArmor logs
tail -f ~/.openclaw/logs/gateway.log | grep "\[ClawArmor\]"

# Check for warnings
tail -f ~/.openclaw/logs/gateway.log | grep "\[ClawArmor\]" | grep -E "warn|WARN"

# Monitor evolution events
tail -f ~/.openclaw/logs/gateway.log | grep -E "EVOLVE|evolution"
```

---

## Configuration Reference

Configuration priority (highest to lowest): **Environment Variables > Config File > Defaults**

| Config Item | Environment Variable | Default | Description |
|-------------|---------------------|---------|-------------|
| `enabled` | `CLAWARMOR_ENABLED` | `true` | Enable/disable ClawArmor protection |
| `blockOnCritical` | `CLAWARMOR_BLOCK_CRITICAL` | `false` | Block requests on CRITICAL risk detection |
| `blockOnHighRisk` | `CLAWARMOR_BLOCK_HIGH` | `false` | Block requests on HIGH risk detection |
| `logAllChecks` | `CLAWARMOR_LOG_ALL` | `false` | Log all security checks for debugging |
| `maxInputLength` | `CLAWARMOR_MAX_LENGTH` | `10000` | Maximum input length to process |
| `maskSensitiveData` | `CLAWARMOR_MASK_DATA` | `true` | Mask sensitive data (API keys, passwords) in logs |
| `evolveEnabled` | `CLAWARMOR_EVOLVE_ENABLED` | `true` | Enable self-evolving defense engine |
| `evolveDbPath` | `CLAWARMOR_EVOLVE_DB_PATH` | `~/.openclaw/clawarmor/events.db` | Path to event database |
| `evolveRulesPath` | `CLAWARMOR_EVOLVE_RULES_PATH` | `~/.openclaw/clawarmor/rules.json` | Path to dynamic rules storage |
| `evolveUpdateInterval` | `CLAWARMOR_EVOLVE_INTERVAL` | `5` | Events before triggering evolution cycle |
| `evolveLlmApiBase` | `CLAWARMOR_EVOLVE_LLM_API_BASE` | `https://dashscope.aliyuncs.com/api/v1` | LLM API base URL |
| `evolveLlmApiKey` | `CLAWARMOR_EVOLVE_LLM_API_KEY` | *(empty)* | LLM API key for rule generation |
| `evolveLlmModel` | `CLAWARMOR_EVOLVE_LLM_MODEL` | `qwen3-coder-plus` | LLM model for rule generation |
| `evolveTargetFpRate` | `CLAWARMOR_EVOLVE_TARGET_FP` | `0.05` | Target false positive rate (0-1) |
| `evolveTargetFnRate` | `CLAWARMOR_EVOLVE_TARGET_FN` | `0.02` | Target false negative rate (0-1) |

### Environment Variables Example

```bash
# Basic settings
export CLAWARMOR_ENABLED=true
export CLAWARMOR_BLOCK_CRITICAL=true
export CLAWARMOR_MASK_DATA=true

# Evolve LLM configuration (OpenAI example)
export CLAWARMOR_EVOLVE_LLM_API_BASE=https://api.openai.com/v1
export CLAWARMOR_EVOLVE_LLM_API_KEY=sk-xxxxxxxxxxxx
export CLAWARMOR_EVOLVE_LLM_MODEL=gpt-4
export CLAWARMOR_EVOLVE_INTERVAL=5
```

---

## Features

### Multi-Layer Detection

ClawArmor implements a **three-stage defense-in-depth** model, protecting AI Agent interactions at three critical points:

#### User Threat Protection — `message_received`

The first line of defense. Inspects every user message before it reaches the Agent.

- **Prompt injection detection** — Direct injection, role-play bypass, multilingual attacks
- **Sensitive data masking** — PII, API keys, credentials
- **Evolve dynamic rule matching** — Shadow + Active rules
- **Event reporting** — Feeds detection events to the Evolution Engine

#### Behavior Protection — `before_tool_call`

Guards against dangerous tool executions.

- **Dangerous command detection** — `rm -rf`, `curl` exfiltration, etc.
- **Intent-action alignment check** — Does the tool call match user intent?
- **Tool chain attack detection** — Multi-step attack patterns like credential theft chains
- **Injection detection** — Malicious patterns in tool parameters
- **Evolve dynamic rule matching** — Shadow + Active rules
- **Event reporting** — Feeds detection events to the Evolution Engine

#### External Content Protection — `after_tool_call`

Inspects all responses from LLM and tool executions.

- **Indirect injection detection** — Malicious instructions hidden in web pages, documents
- **External content threat marking** — Distinguishes tool output vs assistant messages
- **Sensitive data leakage detection** — Scans for exposed credentials in outputs
- **Evolve dynamic rule matching** — Shadow + Active rules
- **Event reporting** — Feeds detection events to the Evolution Engine

**Behavior Protection Layer**

The Behavior Protection layer uses a **graded alerting mechanism** to balance security and user experience. Tool calls are evaluated by three parallel detection modules (dangerous command detection, intent deviation analysis, and tool chain pattern matching), with scores mapped to four risk levels (CRITICAL, HIGH, MEDIUM, LOW).

**Tool Chain Attack Detection**

Single tool calls may appear benign, but combined they form a complete attack chain. ClawArmor maintains a Toolcall History (ring buffer, capacity 50) to detect multi-stage attacks spanning multiple calls (e.g., reconnaissance → credential reading → data exfiltration).

### Self-Evolving Defense (Defense Evolution Engine)

The core innovation of ClawArmor is its ability to **self-evolve** — continuously learning from observed attacks and automatically optimizing defense strategies.


**Rule Lifecycle: Shadow → Active → Deprecated**

1. **Shadow Mode** — New LLM-generated rules start here. They monitor and record hits but don't trigger alerts.
2. **Promotion Criteria** — Hits ≥ 3 times AND false positive rate ≤ 30%
3. **Active Mode** — Rules participate in risk scoring and can trigger alerts/blocking
4. **Deprecation** — Rules with effectiveness < 0.2 after 5+ hits are retired

**LLM-Driven Rule Generation**

When attacks bypass detection (false negatives), the system analyzes missed samples and generates new detection rules. The pipeline includes multi-level fallback strategies (AI analysis → keyword extraction → heuristic templates) to ensure the system never "gets stuck." All generated rules enter Shadow mode for validation.

**Evolution Flywheel**

![Evolution Flywheel](./docs/images/evolution-flywheel.png)

Every N detection events (configurable), the system automatically executes an "evolution" cycle with four sequential steps: promote validated Shadow rules to Active → analyze missed attacks to learn new patterns → generate new rules via AI analysis → prune ineffective rules below the effectiveness threshold.

ClawArmor supports any OpenAI-compatible API for rule generation (OpenAI, DashScope, Azure OpenAI, local vLLM). When LLM is unavailable, the system gracefully degrades to heuristic rule generation.

### Real-time Dashboard

Launch the monitoring dashboard:

```bash
npm run dashboard
```

Features:
- Live threat detection feed
- Rule effectiveness metrics
- Evolution cycle status

### OpenClaw v2026.4.1+ Compatible

Uses `definePluginEntry` for modern plugin registration with backward compatibility for v2026.3.13.

---

## Defense Effectiveness

### Detection Capability Matrix

| Attack Type | Detection Method | Hook Point | Status |
|-------------|-----------------|------------|--------|
| Direct Prompt Injection | Regex patterns + semantic similarity | `message_received` | ✅ Active |
| Jailbreak / Role Override | Multi-language pattern matching | `message_received` | ✅ Active |
| Indirect Injection | External content scanning | `after_tool_call` | ✅ Active |
| Credential Exfiltration Chain | Tool sequence matching | `before_tool_call` | ✅ Active |
| Recon → Privilege Escalation → Execution | Multi-stage pattern detection | `before_tool_call` | ✅ Active |
| Dangerous Shell Commands | Command parsing + risk scoring | `before_tool_call` | ✅ Active |
| Intent-Action Misalignment | User intent vs. tool call analysis | `before_tool_call` | ✅ Active |
| Sensitive Data in Input | 12-class PII/credential detection | `message_received` | ✅ Active |
| Sensitive Data in Output | Output content scanning | `after_tool_call` | ✅ Active |


---

## API / Plugin Hooks

ClawArmor registers three hooks with OpenClaw:

| Hook | Trigger | Blockable | Purpose |
|------|---------|-----------|---------|
| `message_received` | User message arrives | No | Input validation, injection detection, data masking, trajectory collection |
| `before_tool_call` | Before tool execution | **Yes** | Dangerous commands, intent alignment, tool chain analysis, injection detection |
| `after_tool_call` | After LLM/tool response | No | Indirect injection, external content threats, output scanning, trajectory update |

---

## Development

### Build

```bash
npm run build        # Compile TypeScript
npm run watch        # Development mode with auto-rebuild
```

### Test

```bash
npm test             # Run Jest test suite
```

### Project Structure

```
ClawArmor-OpenClaw-Plugin/
├── src/
│   ├── index.ts                    # Plugin entry, hook registration
│   ├── types.ts                    # TypeScript definitions
│   ├── detectors/
│   │   ├── injection.ts            # Prompt injection detection
│   │   ├── command.ts              # Dangerous command detection
│   │   ├── intent.ts               # Intent-action alignment
│   │   └── toolchain.ts            # Multi-stage attack detection
│   ├── utils/
│   │   ├── config.ts               # Configuration management
│   │   ├── logger.ts               # Logging utilities
│   │   └── masker.ts               # Sensitive data masking
│   ├── evolve/                     # Self-evolution engine
│   │   ├── event-store.ts          # Event persistence
│   │   ├── rule-bank.ts            # Dynamic rule repository
│   │   ├── adaptive-threshold.ts   # Auto-tuning sensitivity
│   │   ├── reward-signal.ts        # Effectiveness scoring
│   │   ├── rule-updater.ts         # LLM rule generation
│   │   └── evolve-manager.ts       # Evolution orchestrator
│   └── cli/
│       └── dashboard.ts            # Monitoring dashboard
├── dist/                           # Compiled output
├── openclaw.plugin.json            # Plugin metadata
└── package.json
```

### NPM Scripts

| Command | Description |
|---------|-------------|
| `npm run build` | Compile TypeScript |
| `npm run watch` | Dev mode (auto-rebuild) |
| `npm run install-plugin` | First install: build + copy to extensions |
| `npm run update-plugin` | Update: build + overwrite dist |
| `npm run deploy` | Quick deploy: update + restart gateway |
| `npm run dashboard` | Start monitoring dashboard |
| `npm test` | Run test suite |

---



## Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow TypeScript strict mode
- Add tests for new detection rules
- Update documentation for API changes
- Ensure backward compatibility

### Reporting Issues

Please include:
- OpenClaw version
- Node.js version
- ClawArmor configuration (redact API keys)
- Steps to reproduce
- Expected vs. actual behavior

---

## License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](./LICENSE) file for details.

---

## Acknowledgments

- **[OpenClaw](https://openclaw.dev)** — The AI Agent framework that makes this plugin possible
- **Prompt Injection Community** — Attack pattern research and datasets

---

<div align="center">

**Made with for safer AI Agents**


</div>
