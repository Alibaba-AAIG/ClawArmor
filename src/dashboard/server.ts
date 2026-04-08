/**
 * ClawArmor Dashboard Server
 * Real-time pixel armor defense visualization
 * Ported from ClawArmor Python implementation
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { logger } from '../utils';

export interface DashboardConfig {
  enabled: boolean;
  port: number;
  host: string;
  autoOpen: boolean;
}

export interface DashboardStats {
  totalEvents: number;
  blockedCount: number;
  activeRules: number;
  shadowRules: number;
  threshold: number;
  isEvolving: boolean;
}

export interface DashboardRule {
  ruleId: string;
  title: string;
  status: string;
  hitCount: number;
  category: string;
}

export interface DashboardLog {
  text: string;
  timestamp: number;
  level: string;
}

const DEFAULT_CONFIG: DashboardConfig = {
  enabled: true,
  port: 18790,
  host: '127.0.0.1',
  autoOpen: false
};

// WebSocket types (optional)
type WsServer = any;
type WsClient = any;

export class DashboardServer {
  private config: DashboardConfig;
  private server: http.Server | null = null;
  private wss: WsServer = null;
  private clients: Set<WsClient> = new Set();
  private running: boolean = false;
  private logPath: string;
  private eventsPath: string;
  private rulesPath: string;
  private lastLogSize: number = 0;
  private statsInterval: NodeJS.Timeout | null = null;
  private logInterval: NodeJS.Timeout | null = null;
  private wsAvailable: boolean = false;

  // Callbacks for data retrieval
  private getStatsCallback: (() => Promise<DashboardStats>) | null = null;
  private getRulesCallback: (() => Promise<DashboardRule[]>) | null = null;

  constructor(config: Partial<DashboardConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logPath = path.join(os.homedir(), '.openclaw/logs/gateway.log');
    this.eventsPath = path.join(os.homedir(), '.openclaw/clawarmor/events.db');
    this.rulesPath = path.join(os.homedir(), '.openclaw/clawarmor/rules.json');

    // Check if ws module is available
    try {
      require('ws');
      this.wsAvailable = true;
    } catch {
      this.wsAvailable = false;
      logger.warn('[Dashboard] ws module not available, WebSocket features disabled');
    }
  }

  /**
   * Set callbacks for data retrieval
   */
  setDataCallbacks(
    getStats: () => Promise<DashboardStats>,
    getRules: () => Promise<DashboardRule[]>
  ): void {
    this.getStatsCallback = getStats;
    this.getRulesCallback = getRules;
  }

  /**
   * Start the dashboard server
   */
  async start(): Promise<void> {
    if (this.running || !this.config.enabled) return;

    return new Promise((resolve, reject) => {
      try {
        // Create HTTP server
        this.server = http.createServer((req, res) => this.handleRequest(req, res));

        // Create WebSocket server if available
        if (this.wsAvailable) {
          try {
            const { WebSocketServer } = require('ws');
            this.wss = new WebSocketServer({ server: this.server });
            this.wss.on('connection', (ws: WsClient) => this.handleWebSocket(ws));
          } catch (err) {
            logger.warn(`[Dashboard] WebSocket setup failed: ${err}`);
          }
        }

        // Start listening
        this.server.listen(this.config.port, this.config.host, () => {
          this.running = true;
          logger.info(`[Dashboard] Server started at http://${this.config.host}:${this.config.port}`);
          logger.info(`[Dashboard] WebSocket: ${this.wsAvailable ? 'enabled' : 'disabled (ws module not found)'}`);
          
          // Start periodic updates
          this.startPeriodicUpdates();
          
          resolve();
        });

        this.server.on('error', (err) => {
          logger.error(`[Dashboard] Server error: ${err}`);
          reject(err);
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  /**
   * Stop the dashboard server
   */
  async stop(): Promise<void> {
    if (!this.running) return;

    // Stop periodic updates
    if (this.statsInterval) {
      clearInterval(this.statsInterval);
      this.statsInterval = null;
    }
    if (this.logInterval) {
      clearInterval(this.logInterval);
      this.logInterval = null;
    }

    // Close all WebSocket connections
    for (const client of this.clients) {
      try { client.close(); } catch {}
    }
    this.clients.clear();

    // Close WebSocket server
    if (this.wss) {
      try { this.wss.close(); } catch {}
      this.wss = null;
    }

    // Close HTTP server
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => {
          this.server = null;
          this.running = false;
          logger.info('[Dashboard] Server stopped');
          resolve();
        });
      });
    }
  }

  /**
   * Handle HTTP requests
   */
  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = req.url || '/';

    try {
      if (url === '/' || url === '/index.html') {
        this.serveHtml(res);
      } else if (url === '/api/stats') {
        this.serveStats(res);
      } else if (url === '/api/rules') {
        this.serveRules(res);
      } else if (url.startsWith('/api/logs')) {
        this.serveLogs(res, url);
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
      }
    } catch (err) {
      logger.error(`[Dashboard] Request error: ${err}`);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  }

  /**
   * Serve the dashboard HTML
   */
  private serveHtml(res: http.ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(DASHBOARD_HTML);
  }

  /**
   * Serve stats API
   */
  private async serveStats(res: http.ServerResponse): Promise<void> {
    try {
      let stats: DashboardStats;
      
      if (this.getStatsCallback) {
        stats = await this.getStatsCallback();
      } else {
        stats = await this.getStatsFromFile();
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(stats));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(err) }));
    }
  }

  /**
   * Serve rules API
   */
  private async serveRules(res: http.ServerResponse): Promise<void> {
    try {
      let rules: DashboardRule[];
      
      if (this.getRulesCallback) {
        rules = await this.getRulesCallback();
      } else {
        rules = await this.getRulesFromFile();
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(rules));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(err) }));
    }
  }

  /**
   * Serve logs API
   */
  private serveLogs(res: http.ServerResponse, url: string): void {
    const match = url.match(/limit=(\d+)/);
    const limit = match ? parseInt(match[1], 10) : 50;

    try {
      const logs = this.getLogsFromFile(limit);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(logs));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(err) }));
    }
  }

  /**
   * Handle WebSocket connection
   */
  private handleWebSocket(ws: WsClient): void {
    if (!this.wsAvailable) return;
    
    this.clients.add(ws);
    logger.info(`[Dashboard] Client connected, total: ${this.clients.size}`);

    ws.on('close', () => {
      this.clients.delete(ws);
      logger.info(`[Dashboard] Client disconnected, total: ${this.clients.size}`);
    });

    ws.on('error', (err: Error) => {
      logger.error(`[Dashboard] WebSocket error: ${err}`);
      this.clients.delete(ws);
    });

    // Send initial data
    this.sendToClient(ws, 'connected', { 
      message: 'Connected to ClawArmor Dashboard',
      timestamp: Date.now()
    });
  }

  /**
   * Send data to a specific client
   */
  private sendToClient(ws: WsClient, event: string, data: unknown): void {
    if (!this.wsAvailable) return;
    try {
      const { WebSocket } = require('ws');
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ event, data }));
      }
    } catch {}
  }

  /**
   * Broadcast to all clients
   */
  broadcast(event: string, data: unknown): void {
    if (!this.wsAvailable || this.clients.size === 0) return;
    
    const message = JSON.stringify({ event, data });
    const { WebSocket } = require('ws');
    
    for (const client of this.clients) {
      try {
        if (client.readyState === WebSocket.OPEN) {
          client.send(message);
        }
      } catch {}
    }
  }

  /**
   * Start periodic updates
   */
  private startPeriodicUpdates(): void {
    // Stats update every 3 seconds
    this.statsInterval = setInterval(async () => {
      try {
        const stats = this.getStatsCallback 
          ? await this.getStatsCallback() 
          : await this.getStatsFromFile();
        this.broadcast('stats', stats);
      } catch (err) {
        logger.error(`[Dashboard] Stats update error: ${err}`);
      }
    }, 3000);

    // Log polling every 500ms
    this.logInterval = setInterval(() => {
      try {
        this.checkLogUpdates();
      } catch {
        // Ignore errors
      }
    }, 500);
  }

  /**
   * Check for log file updates
   */
  private checkLogUpdates(): void {
    if (!fs.existsSync(this.logPath)) return;

    const stats = fs.statSync(this.logPath);
    if (stats.size <= this.lastLogSize) {
      this.lastLogSize = stats.size;
      return;
    }

    // Read new content
    const fd = fs.openSync(this.logPath, 'r');
    const buffer = Buffer.alloc(stats.size - this.lastLogSize);
    fs.readSync(fd, buffer, 0, buffer.length, this.lastLogSize);
    fs.closeSync(fd);

    this.lastLogSize = stats.size;
    const newContent = buffer.toString('utf-8');

    // Parse and send new log lines
    const lines = newContent.split('\n').filter(l => l.trim() && l.includes('[ClawArmor]'));
    for (const line of lines) {
      this.broadcast('log', {
        text: line.trim(),
        timestamp: Date.now()
      });
    }
  }

  /**
   * Get stats from file (fallback)
   */
  private async getStatsFromFile(): Promise<DashboardStats> {
    let totalEvents = 0;
    let blockedCount = 0;

    try {
      if (fs.existsSync(this.eventsPath)) {
        const data = JSON.parse(fs.readFileSync(this.eventsPath, 'utf-8'));
        const events = data.events || [];
        totalEvents = events.length;
        blockedCount = events.filter((e: { blocked?: boolean }) => e.blocked).length;
      }
    } catch {
      // Ignore
    }

    let activeRules = 0;
    let shadowRules = 0;

    try {
      if (fs.existsSync(this.rulesPath)) {
        const data = JSON.parse(fs.readFileSync(this.rulesPath, 'utf-8'));
        const rules = data.rules || {};
        for (const rule of Object.values(rules) as Array<{ status?: string }>) {
          if (rule.status === 'active') activeRules++;
          else if (rule.status === 'shadow') shadowRules++;
        }
      }
    } catch {
      // Ignore
    }

    return {
      totalEvents,
      blockedCount,
      activeRules,
      shadowRules,
      threshold: 0.8,
      isEvolving: false
    };
  }

  /**
   * Get rules from file (fallback)
   */
  private async getRulesFromFile(): Promise<DashboardRule[]> {
    try {
      if (fs.existsSync(this.rulesPath)) {
        const data = JSON.parse(fs.readFileSync(this.rulesPath, 'utf-8'));
        const rules = data.rules || {};
        return Object.entries(rules)
          .map(([id, r]: [string, any]) => ({
            ruleId: id,
            title: r.title || id,
            status: r.status || 'unknown',
            hitCount: r.hitCount || 0,
            category: r.category || 'unknown'
          }))
          .sort((a, b) => {
            // Sort: active > shadow > deprecated
            const order = { active: 0, shadow: 1, deprecated: 2 };
            return (order[a.status as keyof typeof order] ?? 3) - (order[b.status as keyof typeof order] ?? 3);
          });
      }
    } catch {
      // Ignore
    }
    return [];
  }

  /**
   * Get logs from file
   */
  private getLogsFromFile(limit: number): DashboardLog[] {
    const logs: DashboardLog[] = [];
    
    try {
      if (fs.existsSync(this.logPath)) {
        const content = fs.readFileSync(this.logPath, 'utf-8');
        const lines = content.split('\n').filter(l => l.includes('[ClawArmor]')).slice(-limit);
        
        for (const line of lines) {
          let level = 'info';
          if (line.includes('WARN') || line.includes('[EVOLVE')) level = 'warn';
          if (line.includes('ERROR')) level = 'error';
          
          logs.push({
            text: line.trim(),
            timestamp: Date.now(),
            level
          });
        }
      }
    } catch {
      // Ignore
    }

    return logs;
  }

  /**
   * Check if server is running
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Get server URL
   */
  getUrl(): string {
    return `http://${this.config.host}:${this.config.port}`;
  }
}

/**
 * Embedded Dashboard HTML
 * Pixel-art style defense visualization
 */
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>⚔ ClawArmor Defense System</title>
  <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Press Start 2P', monospace;
      background: #0a0a0f;
      color: #00ff88;
      min-height: 100vh;
      overflow-x: hidden;
    }
    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 20px;
      padding-bottom: 180px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 20px;
      border: 2px solid #00ff88;
      margin-bottom: 20px;
      background: rgba(0, 255, 136, 0.05);
    }
    .header h1 {
      font-size: 16px;
      text-shadow: 0 0 10px #00ff88;
    }
    .status {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 10px;
    }
    .status-dot {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background: #00ff88;
      animation: pulse 2s infinite;
    }
    .status-dot.offline { background: #ff4444; animation: none; }
    @keyframes pulse {
      0%, 100% { opacity: 1; box-shadow: 0 0 10px #00ff88; }
      50% { opacity: 0.5; box-shadow: 0 0 5px #00ff88; }
    }
    .main-grid {
      display: grid;
      grid-template-columns: 250px 1fr 280px;
      gap: 20px;
      min-height: 500px;
    }
    @media (max-width: 1200px) {
      .main-grid { grid-template-columns: 1fr; }
    }
    .panel {
      border: 2px solid #00ff88;
      background: rgba(0, 255, 136, 0.03);
      padding: 15px;
    }
    .panel-title {
      font-size: 10px;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 1px solid #00ff88;
      text-transform: uppercase;
    }
    .stats-grid {
      display: grid;
      gap: 15px;
    }
    .stat-item {
      padding: 10px;
      background: rgba(0, 255, 136, 0.05);
      border: 1px solid #00ff88;
    }
    .stat-label {
      font-size: 8px;
      color: #888;
      margin-bottom: 5px;
    }
    .stat-value {
      font-size: 20px;
      text-shadow: 0 0 5px #00ff88;
    }
    .stat-value.warning { color: #ffaa00; text-shadow: 0 0 5px #ffaa00; }
    .stat-value.danger { color: #ff4444; text-shadow: 0 0 5px #ff4444; }
    .battlefield {
      position: relative;
      min-height: 400px;
      background: 
        linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
      background-size: 20px 20px;
      overflow: hidden;
    }
    .armor-wrapper {
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      z-index: 100;
      pointer-events: none;
    }
    .armor {
      font-size: 120px;
      text-align: center;
      filter: drop-shadow(0 0 20px currentColor);
      transition: all 0.5s;
    }
    .armor.level-1 { color: #666; }
    .armor.level-2 { color: #00ff88; }
    .armor.level-3 { color: #00aaff; }
    .armor.level-4 { color: #ffaa00; }
    .armor.level-5 { color: #ffd700; animation: glow 1s infinite alternate; }
    @keyframes glow {
      from { filter: drop-shadow(0 0 20px currentColor); }
      to { filter: drop-shadow(0 0 40px currentColor); }
    }
    .armor-level {
      text-align: center;
      font-size: 10px;
      margin-top: 10px;
    }
    .bullet {
      position: absolute;
      font-size: 24px;
      animation: flyIn 1s forwards;
      z-index: 50;
    }
    @keyframes flyIn {
      from { transform: translateX(100vw); opacity: 1; }
      to { transform: translateX(0); opacity: 0; }
    }
    .rules-list {
      max-height: 300px;
      overflow-y: auto;
    }
    .rule-item {
      padding: 8px;
      margin-bottom: 5px;
      background: rgba(0, 255, 136, 0.05);
      border-left: 3px solid #00ff88;
      font-size: 8px;
    }
    .rule-item.shadow { border-left-color: #aa44ff; }
    .rule-item.deprecated { border-left-color: #666; opacity: 0.5; }
    .rule-title {
      color: #fff;
      margin-bottom: 3px;
      word-break: break-all;
    }
    .rule-hits {
      color: #888;
      font-size: 7px;
    }
    .footer {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 20px;
      margin-top: 20px;
      padding: 15px;
      border: 2px solid #00ff88;
      background: rgba(0, 255, 136, 0.03);
      font-size: 10px;
    }
    .footer-item {
      text-align: center;
    }
    .footer-label { color: #888; }
    .footer-value { margin-top: 5px; }
    .log-container {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      height: 150px;
      background: rgba(10, 10, 15, 0.95);
      border-top: 2px solid #00ff88;
      overflow-y: auto;
      padding: 10px;
      font-size: 8px;
    }
    .log-line {
      padding: 3px 0;
      border-bottom: 1px solid rgba(0, 255, 136, 0.1);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .log-line.warn { color: #ffaa00; }
    .log-line.error { color: #ff4444; }
    .log-line.evolve { color: #aa44ff; }
    .upgrade-flash {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(255, 215, 0, 0.3);
      pointer-events: none;
      animation: flash 0.5s forwards;
      z-index: 200;
    }
    @keyframes flash {
      to { opacity: 0; }
    }
    .upgrade-text {
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      font-size: 24px;
      color: #ffd700;
      text-shadow: 0 0 20px #ffd700;
      animation: popIn 1s forwards;
      z-index: 201;
    }
    @keyframes popIn {
      0% { transform: translate(-50%, -50%) scale(0); opacity: 0; }
      50% { transform: translate(-50%, -50%) scale(1.2); opacity: 1; }
      100% { transform: translate(-50%, -50%) scale(1); opacity: 0; }
    }
    .attack-counter {
      margin-top: 20px;
    }
    .attack-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px;
      margin-bottom: 5px;
      background: rgba(0, 255, 136, 0.05);
      font-size: 8px;
    }
    .attack-icon { font-size: 16px; }
    .attack-label { flex: 1; }
    .attack-count { color: #888; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>⚔ CLAWARMOR DEFENSE SYSTEM ⚔</h1>
      <div class="status">
        <div class="status-dot" id="statusDot"></div>
        <span id="statusText">CONNECTING...</span>
      </div>
    </div>

    <div class="main-grid">
      <div class="panel">
        <div class="panel-title">📊 Stats</div>
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-label">TOTAL EVENTS</div>
            <div class="stat-value" id="totalEvents">0</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">BLOCKED</div>
            <div class="stat-value" id="blockedCount">0</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">THRESHOLD</div>
            <div class="stat-value" id="threshold">0.80</div>
          </div>
        </div>
        
        <div class="attack-counter">
          <div class="panel-title" style="margin-top: 20px;">🎯 Incoming</div>
          <div class="attack-item">
            <span class="attack-icon">🟣</span>
            <span class="attack-label">Shadow Hits</span>
            <span class="attack-count" id="shadowHits">0</span>
          </div>
          <div class="attack-item">
            <span class="attack-icon">🛡️</span>
            <span class="attack-label">Blocked</span>
            <span class="attack-count" id="blockedHits">0</span>
          </div>
          <div class="attack-item">
            <span class="attack-icon">⬆️</span>
            <span class="attack-label">Evolved</span>
            <span class="attack-count" id="evolvedCount">0</span>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-title">⚔ Battlefield</div>
        <div class="battlefield" id="battlefield"></div>
      </div>

      <div class="panel">
        <div class="panel-title">📜 Evolved Rules</div>
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-label">ACTIVE</div>
            <div class="stat-value" id="activeRules" style="color: #00ff88;">0</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">SHADOW</div>
            <div class="stat-value" id="shadowRules" style="color: #aa44ff;">0</div>
          </div>
        </div>
        <div class="rules-list" id="rulesList" style="margin-top: 15px;"></div>
      </div>
    </div>

    <div class="footer">
      <div class="footer-item">
        <div class="footer-label">ACTIVE RULES</div>
        <div class="footer-value" id="footerActive">0</div>
      </div>
      <div class="footer-item">
        <div class="footer-label">SHADOW RULES</div>
        <div class="footer-value" id="footerShadow">0</div>
      </div>
      <div class="footer-item">
        <div class="footer-label">LAST EVOLUTION</div>
        <div class="footer-value" id="lastEvolution">--:--:--</div>
      </div>
    </div>
  </div>

  <div class="armor-wrapper">
    <div class="armor level-1" id="armor">🛡️</div>
    <div class="armor-level" id="armorLevel">LV.1 BASIC</div>
  </div>

  <div class="log-container" id="logContainer"></div>

  <script>
    let ws = null;
    let reconnectTimer = null;
    let shadowHitCount = 0;
    let blockedHitCount = 0;
    let evolvedCount = 0;
    let lastRuleCount = 0;

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = protocol + '//' + window.location.host;
      
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          document.getElementById('statusDot').classList.remove('offline');
          document.getElementById('statusText').textContent = 'ONLINE';
          addLog('Connected to ClawArmor Dashboard', 'info');
        };

        ws.onclose = () => {
          document.getElementById('statusDot').classList.add('offline');
          document.getElementById('statusText').textContent = 'OFFLINE';
          addLog('Disconnected, reconnecting...', 'warn');
          reconnectTimer = setTimeout(connect, 3000);
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            handleMessage(msg.event, msg.data);
          } catch (e) {}
        };

        ws.onerror = () => {
          addLog('WebSocket error, using polling mode', 'warn');
          startPolling();
        };
      } catch (e) {
        addLog('WebSocket not available, using polling mode', 'warn');
        startPolling();
      }
    }

    function startPolling() {
      setInterval(async () => {
        try {
          const res = await fetch('/api/stats');
          const stats = await res.json();
          updateStats(stats);
        } catch {}
      }, 3000);

      setInterval(async () => {
        try {
          const res = await fetch('/api/logs?limit=10');
          const logs = await res.json();
          for (const log of logs.slice(-5)) {
            addLog(log.text, log.level);
          }
        } catch {}
      }, 2000);
    }

    function handleMessage(event, data) {
      switch (event) {
        case 'stats':
          updateStats(data);
          break;
        case 'log':
          handleLog(data);
          break;
        case 'rules':
          updateRules(data);
          break;
      }
    }

    function updateStats(stats) {
      document.getElementById('totalEvents').textContent = stats.totalEvents;
      document.getElementById('blockedCount').textContent = stats.blockedCount;
      document.getElementById('activeRules').textContent = stats.activeRules;
      document.getElementById('shadowRules').textContent = stats.shadowRules;
      document.getElementById('threshold').textContent = stats.threshold.toFixed(2);
      document.getElementById('footerActive').textContent = stats.activeRules;
      document.getElementById('footerShadow').textContent = stats.shadowRules;

      const totalRules = stats.activeRules + stats.shadowRules;
      updateArmorLevel(totalRules);

      if (stats.isEvolving) {
        addLog('Evolution in progress...', 'evolve');
      }

      if (totalRules > lastRuleCount && lastRuleCount > 0) {
        showUpgrade();
      }
      lastRuleCount = totalRules;
    }

    function updateArmorLevel(ruleCount) {
      const armor = document.getElementById('armor');
      const levelText = document.getElementById('armorLevel');
      
      let level, text;
      if (ruleCount >= 20) { level = 5; text = 'LV.5 LEGENDARY'; }
      else if (ruleCount >= 15) { level = 4; text = 'LV.4 ELITE'; }
      else if (ruleCount >= 10) { level = 3; text = 'LV.3 ADVANCED'; }
      else if (ruleCount >= 5) { level = 2; text = 'LV.2 ENHANCED'; }
      else { level = 1; text = 'LV.1 BASIC'; }

      armor.className = 'armor level-' + level;
      levelText.textContent = text;
    }

    function showUpgrade() {
      const flash = document.createElement('div');
      flash.className = 'upgrade-flash';
      document.body.appendChild(flash);
      setTimeout(() => flash.remove(), 500);

      const text = document.createElement('div');
      text.className = 'upgrade-text';
      text.textContent = '⚔ ARMOR UPGRADED! ⚔';
      document.body.appendChild(text);
      setTimeout(() => text.remove(), 1000);
    }

    function handleLog(data) {
      addLog(data.text, getLogLevel(data.text));

      if (data.text.includes('[EVOLVE-SHADOW]')) {
        createBullet('🟣');
        shadowHitCount++;
        document.getElementById('shadowHits').textContent = shadowHitCount;
      } else if (data.text.includes('[EVOLVE-ACTIVE]')) {
        createBullet('🔴');
        blockedHitCount++;
        document.getElementById('blockedHits').textContent = blockedHitCount;
      } else if (data.text.includes('Promoted')) {
        evolvedCount++;
        document.getElementById('evolvedCount').textContent = evolvedCount;
        document.getElementById('lastEvolution').textContent = new Date().toLocaleTimeString();
      }
    }

    function getLogLevel(text) {
      if (text.includes('ERROR')) return 'error';
      if (text.includes('WARN') || text.includes('EVOLVE')) return 'warn';
      return '';
    }

    function addLog(text, level) {
      const container = document.getElementById('logContainer');
      const line = document.createElement('div');
      line.className = 'log-line ' + level;
      line.textContent = text;
      container.appendChild(line);
      container.scrollTop = container.scrollHeight;

      while (container.children.length > 100) {
        container.removeChild(container.firstChild);
      }
    }

    function createBullet(emoji) {
      const battlefield = document.getElementById('battlefield');
      const bullet = document.createElement('div');
      bullet.className = 'bullet';
      bullet.textContent = emoji;
      bullet.style.top = (Math.random() * 300 + 50) + 'px';
      bullet.style.right = '0';
      battlefield.appendChild(bullet);

      setTimeout(() => {
        bullet.classList.add('blocked');
        setTimeout(() => bullet.remove(), 500);
      }, 1000);
    }

    function updateRules(rules) {
      const container = document.getElementById('rulesList');
      container.innerHTML = '';

      for (const rule of rules.slice(0, 20)) {
        const item = document.createElement('div');
        item.className = 'rule-item ' + rule.status;
        item.innerHTML = '<div class="rule-title">' + rule.title + '</div>' +
                        '<div class="rule-hits">hits: ' + rule.hitCount + ' | ' + rule.status + '</div>';
        container.appendChild(item);
      }
    }

    // Initial load
    fetch('/api/stats').then(r => r.json()).then(updateStats).catch(() => {});
    fetch('/api/rules').then(r => r.json()).then(updateRules).catch(() => {});
    fetch('/api/logs?limit=20').then(r => r.json()).then(logs => {
      logs.forEach(l => addLog(l.text, l.level));
    }).catch(() => {});

    // Start connection
    connect();
  </script>
</body>
</html>`;
