#!/usr/bin/env node
/**
 * ClawArmor Dashboard CLI
 * Standalone dashboard server for monitoring ClawArmor defense
 * 
 * Usage:
 *   clawarmor-dashboard [--port 18790] [--host 127.0.0.1]
 */

import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import * as http from 'http';

// Parse command line args
const args = process.argv.slice(2);
let port = 18790;
let host = '127.0.0.1';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port' || args[i] === '-p') {
    port = parseInt(args[++i], 10) || 18790;
  } else if (args[i] === '--host' || args[i] === '-h') {
    host = args[++i] || '127.0.0.1';
  } else if (args[i] === '--help') {
    console.log(`
ClawArmor Dashboard - Real-time defense visualization

Usage:
  clawarmor-dashboard [options]

Options:
  --port, -p    Port to listen on (default: 18790)
  --host, -h    Host to bind to (default: 127.0.0.1)
  --help        Show this help message

Dashboard will monitor:
  - ~/.openclaw/logs/gateway.log     (ClawArmor logs)
  - ~/.openclaw/clawarmor/events.db  (Defense events)
  - ~/.openclaw/clawarmor/rules.json (Evolved rules)
`);
    process.exit(0);
  }
}

// Paths
const logPath = path.join(os.homedir(), '.openclaw/logs/gateway.log');
const eventsPath = path.join(os.homedir(), '.openclaw/clawarmor/events.db');
const rulesPath = path.join(os.homedir(), '.openclaw/clawarmor/rules.json');

let lastLogSize = 0;
let clients: Set<any> = new Set();

// WebSocket support (optional)
let WebSocketServer: any = null;
let WebSocket: any = null;
try {
  const ws = require('ws');
  WebSocketServer = ws.WebSocketServer;
  WebSocket = ws.WebSocket;
} catch {
  console.log('[Dashboard] ws module not available, using polling mode only');
}

// Create HTTP server
const server = http.createServer((req, res) => {
  const url = req.url || '/';

  if (url === '/' || url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(DASHBOARD_HTML);
  } else if (url === '/api/stats') {
    serveStats(res);
  } else if (url === '/api/rules') {
    serveRules(res);
  } else if (url.startsWith('/api/logs')) {
    serveLogs(res, url);
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  }
});

function serveStats(res: http.ServerResponse) {
  let totalEvents = 0;
  let blockedCount = 0;
  let activeRules = 0;
  let shadowRules = 0;
  let threshold = 0.8;

  try {
    if (fs.existsSync(eventsPath)) {
      const data = JSON.parse(fs.readFileSync(eventsPath, 'utf-8'));
      totalEvents = (data.events || []).length;
      blockedCount = (data.events || []).filter((e: any) => e.blocked).length;
      // Read threshold from events.db metadata
      if (data.threshold !== undefined) threshold = data.threshold;
    }
  } catch {}

  try {
    if (fs.existsSync(rulesPath)) {
      const data = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
      const rules = data.rules || {};
      for (const rule of Object.values(rules) as any[]) {
        if (rule.status === 'active') activeRules++;
        else if (rule.status === 'shadow') shadowRules++;
      }
    }
  } catch {}

  // Also try to read threshold from a separate threshold file
  const thresholdPath = path.join(os.homedir(), '.openclaw/clawarmor/threshold.json');
  try {
    if (fs.existsSync(thresholdPath)) {
      const data = JSON.parse(fs.readFileSync(thresholdPath, 'utf-8'));
      if (data.threshold !== undefined) threshold = data.threshold;
    }
  } catch {}

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ totalEvents, blockedCount, activeRules, shadowRules, threshold, isEvolving: false }));
}

function serveRules(res: http.ServerResponse) {
  try {
    if (fs.existsSync(rulesPath)) {
      const data = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
      const rules = data.rules || {};
      const list = Object.entries(rules)
        .map(([id, r]: [string, any]) => ({
          ruleId: id,
          title: r.title || id,
          status: r.status || 'unknown',
          hitCount: r.hitCount || 0,
          category: r.category || 'unknown'
        }))
        .sort((a, b) => {
          const order: Record<string, number> = { active: 0, shadow: 1, deprecated: 2 };
          return (order[a.status] ?? 3) - (order[b.status] ?? 3);
        });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(list));
      return;
    }
  } catch {}
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify([]));
}

function serveLogs(res: http.ServerResponse, url: string) {
  const match = url.match(/limit=(\d+)/);
  const limit = match ? parseInt(match[1], 10) : 50;
  const logs: any[] = [];

  try {
    if (fs.existsSync(logPath)) {
      const content = fs.readFileSync(logPath, 'utf-8');
      const lines = content.split('\n').filter(l => l.includes('[ClawArmor]')).slice(-limit);
      for (const line of lines) {
        let level = 'info';
        if (line.includes('WARN') || line.includes('EVOLVE')) level = 'warn';
        if (line.includes('ERROR')) level = 'error';
        logs.push({ text: line.trim(), timestamp: Date.now(), level });
      }
    }
  } catch {}

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(logs));
}

function broadcast(event: string, data: any) {
  if (!WebSocketServer || clients.size === 0) return;
  const msg = JSON.stringify({ event, data });
  for (const client of clients) {
    try {
      if (client.readyState === WebSocket.OPEN) {
        client.send(msg);
      }
    } catch {}
  }
}

function checkLogUpdates() {
  if (!fs.existsSync(logPath)) return;

  const stats = fs.statSync(logPath);
  if (stats.size <= lastLogSize) {
    lastLogSize = stats.size;
    return;
  }

  const fd = fs.openSync(logPath, 'r');
  const buffer = Buffer.alloc(stats.size - lastLogSize);
  fs.readSync(fd, buffer, 0, buffer.length, lastLogSize);
  fs.closeSync(fd);

  lastLogSize = stats.size;
  const newContent = buffer.toString('utf-8');
  const lines = newContent.split('\n').filter(l => l.trim() && l.includes('[ClawArmor]'));

  for (const line of lines) {
    broadcast('log', { text: line.trim(), timestamp: Date.now() });
  }
}

// Start server
server.listen(port, host, () => {
  console.log(`\n⚔  ClawArmor Dashboard`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`  Dashboard: http://${host}:${port}/`);
  console.log(`  Logs:      ${logPath}`);
  console.log(`  Events:    ${eventsPath}`);
  console.log(`  Rules:     ${rulesPath}`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

  // Start WebSocket if available
  if (WebSocketServer) {
    const wss = new WebSocketServer({ server });
    wss.on('connection', (ws: any) => {
      clients.add(ws);
      ws.on('close', () => clients.delete(ws));
      ws.on('error', () => clients.delete(ws));
      ws.send(JSON.stringify({ event: 'connected', data: { message: 'Connected', timestamp: Date.now() } }));
    });
    console.log('[Dashboard] WebSocket enabled');
  }

  // Start periodic updates
  setInterval(() => {
    // Stats broadcast
    let totalEvents = 0, blockedCount = 0, activeRules = 0, shadowRules = 0;
    try {
      if (fs.existsSync(eventsPath)) {
        const data = JSON.parse(fs.readFileSync(eventsPath, 'utf-8'));
        totalEvents = (data.events || []).length;
        blockedCount = (data.events || []).filter((e: any) => e.blocked).length;
      }
    } catch {}
    try {
      if (fs.existsSync(rulesPath)) {
        const data = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
        for (const r of Object.values(data.rules || {}) as any[]) {
          if (r.status === 'active') activeRules++;
          else if (r.status === 'shadow') shadowRules++;
        }
      }
    } catch {}
    broadcast('stats', { totalEvents, blockedCount, activeRules, shadowRules, threshold: 0.8, isEvolving: false });
  }, 3000);

  // Log polling
  setInterval(checkLogUpdates, 500);
});

// Embedded HTML - Pixel Armor Defense Theme
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ClawArmor Evolve — 盔甲防御系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');
    :root {
      --pixel-size: 4px;
      --bg-dark: #0a0a1a;
      --gold: #ffd700;
      --steel: #4a5568;
      --red: #ef4444;
      --green: #22c55e;
      --blue: #3b82f6;
      --purple: #a855f7;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; image-rendering: pixelated; }
    body { font-family: 'Press Start 2P', monospace; background: var(--bg-dark); color: #e0e0e0; min-height: 100vh; overflow: hidden; }
    
    .header {
      background: linear-gradient(180deg, #1a1a3a 0%, var(--bg-dark) 100%);
      padding: 0.8rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: var(--pixel-size) solid var(--gold);
    }
    .title { font-size: 1rem; color: var(--gold); text-shadow: 2px 2px 0 #000, 4px 4px 0 rgba(255,215,0,0.3); letter-spacing: 2px; }
    .status-indicator { display: flex; align-items: center; gap: 0.5rem; font-size: 0.5rem; color: var(--green); }
    .status-dot { width: 12px; height: 12px; background: var(--green); animation: blink 1s infinite; }
    .status-dot.offline { background: var(--red); animation: none; }
    @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
    
    .main-container { display: grid; grid-template-columns: 300px 1fr 280px; height: calc(100vh - 100px); gap: 1rem; padding: 1rem; padding-bottom: 60px; }
    
    .attack-panel { background: rgba(10, 10, 30, 0.9); border: var(--pixel-size) solid var(--steel); display: flex; flex-direction: column; min-height: 400px; }
    .panel-title { background: var(--steel); color: #fff; padding: 0.5rem; font-size: 0.5rem; text-align: center; text-transform: uppercase; }
    .attack-list { flex: 1; overflow-y: auto; padding: 0.5rem; }
    .attack-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.4rem; margin: 0.3rem 0; font-size: 0.4rem; background: rgba(0,0,0,0.3); border-left: var(--pixel-size) solid var(--red); animation: slideInLeft 0.3s ease; }
    .attack-item.blocked { border-left-color: var(--green); }
    .attack-item.shadow { border-left-color: var(--purple); }
    .attack-item.evolve { border-left-color: var(--gold); background: rgba(255,215,0,0.1); }
    @keyframes slideInLeft { from { transform: translateX(-100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    .attack-icon { font-size: 1rem; }
    .attack-text { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    
    .battlefield {
      position: relative;
      background: radial-gradient(ellipse at center bottom, rgba(50,50,100,0.3) 0%, transparent 70%), linear-gradient(180deg, #0a0a2a 0%, #0f0f2f 50%, #0a0a1a 100%);
      border: var(--pixel-size) solid var(--gold);
      overflow: hidden;
      min-height: 500px;
    }
    .battlefield::before {
      content: '';
      position: absolute;
      inset: 0;
      background-image: linear-gradient(rgba(255,215,0,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,215,0,0.03) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
    }
    
    .armor-wrapper { position: absolute; top: 50%; right: 80px; transform: translateY(-50%); z-index: 10; pointer-events: none; }
    .armor { width: 160px; height: 240px; position: relative; filter: drop-shadow(0 0 30px rgba(255,215,0,0.4)); }
    .armor-head { position: absolute; top: 0; left: 50%; transform: translateX(-50%); width: 80px; height: 70px; background: linear-gradient(180deg, #4a5568 0%, #2d3748 100%); clip-path: polygon(10% 30%, 30% 0%, 70% 0%, 90% 30%, 100% 100%, 0% 100%); border: 3px solid #718096; }
    .armor-visor { position: absolute; top: 30px; left: 50%; transform: translateX(-50%); width: 50px; height: 20px; background: linear-gradient(180deg, #3b82f6 0%, #1d4ed8 100%); clip-path: polygon(0% 50%, 10% 0%, 90% 0%, 100% 50%, 90% 100%, 10% 100%); animation: visorGlow 2s infinite; }
    @keyframes visorGlow { 0%, 100% { box-shadow: 0 0 10px #3b82f6, inset 0 0 10px rgba(255,255,255,0.3); } 50% { box-shadow: 0 0 20px #60a5fa, inset 0 0 15px rgba(255,255,255,0.5); } }
    .armor-torso { position: absolute; top: 65px; left: 50%; transform: translateX(-50%); width: 120px; height: 100px; background: linear-gradient(180deg, #4a5568 0%, #2d3748 50%, #1a202c 100%); clip-path: polygon(0% 0%, 100% 0%, 95% 100%, 5% 100%); border: 3px solid #718096; }
    .armor-core { position: absolute; top: 90px; left: 50%; transform: translateX(-50%); width: 40px; height: 40px; background: radial-gradient(circle, #ffd700 0%, #f59e0b 50%, #d97706 100%); border-radius: 50%; animation: coreGlow 1.5s infinite; }
    @keyframes coreGlow { 0%, 100% { box-shadow: 0 0 20px #ffd700, 0 0 40px rgba(255,215,0,0.5); } 50% { box-shadow: 0 0 30px #ffd700, 0 0 60px rgba(255,215,0,0.7); } }
    .armor-arm { position: absolute; top: 75px; width: 35px; height: 90px; background: linear-gradient(180deg, #4a5568 0%, #2d3748 100%); border: 2px solid #718096; }
    .armor-arm.left { left: 5px; transform: rotate(15deg); border-radius: 10px 10px 5px 15px; }
    .armor-arm.right { right: 5px; transform: rotate(-15deg); border-radius: 10px 10px 15px 5px; }
    .armor-leg { position: absolute; bottom: 0; width: 40px; height: 100px; background: linear-gradient(180deg, #2d3748 0%, #1a202c 100%); border: 2px solid #4a5568; }
    .armor-leg.left { left: 35px; border-radius: 5px 5px 10px 10px; }
    .armor-leg.right { right: 35px; border-radius: 5px 5px 10px 10px; }
    
    .armor.level-2 .armor-head, .armor.level-2 .armor-torso, .armor.level-2 .armor-arm { background: linear-gradient(180deg, #065f46 0%, #064e3b 100%); border-color: #10b981; }
    .armor.level-3 .armor-head, .armor.level-3 .armor-torso, .armor.level-3 .armor-arm { background: linear-gradient(180deg, #1e40af 0%, #1e3a8a 100%); border-color: #3b82f6; }
    .armor.level-3 .armor-core { background: radial-gradient(circle, #60a5fa 0%, #3b82f6 50%, #1d4ed8 100%); }
    .armor.level-4 .armor-head, .armor.level-4 .armor-torso, .armor.level-4 .armor-arm { background: linear-gradient(180deg, #7c2d12 0%, #9a3412 50%, #c2410c 100%); border-color: #f97316; }
    .armor.level-4 .armor-core { background: radial-gradient(circle, #fb923c 0%, #f97316 50%, #ea580c 100%); }
    .armor.level-5 .armor-head, .armor.level-5 .armor-torso, .armor.level-5 .armor-arm { background: linear-gradient(180deg, #ffd700 0%, #f59e0b 50%, #d97706 100%); border-color: #fbbf24; }
    .armor.level-5 .armor-visor { background: linear-gradient(180deg, #ef4444 0%, #dc2626 100%); }
    
    .armor-level { position: absolute; bottom: -40px; left: 50%; transform: translateX(-50%); background: var(--gold); color: #000; padding: 0.3rem 0.8rem; font-size: 0.5rem; white-space: nowrap; }
    .shield-effect { position: absolute; width: 240px; height: 320px; border: 4px solid rgba(255,215,0,0.3); border-radius: 50%; opacity: 0; pointer-events: none; top: 50%; left: 50%; transform: translate(-50%, -50%); }
    .shield-effect.active { animation: shieldPulse 0.5s ease; }
    @keyframes shieldPulse { 0% { opacity: 0; transform: translate(-50%, -50%) scale(0.8); } 50% { opacity: 1; transform: translate(-50%, -50%) scale(1); border-color: rgba(255,215,0,0.8); } 100% { opacity: 0; transform: translate(-50%, -50%) scale(1.2); } }
    
    .projectile { position: absolute; left: 0; font-size: 1.5rem; animation: flyIn 1s linear forwards; z-index: 5; pointer-events: none; }
    @keyframes flyIn { 0% { left: -50px; opacity: 1; } 80% { opacity: 1; } 100% { left: calc(100% - 100px); opacity: 0; } }
    .projectile.blocked { animation: flyInBlocked 0.6s ease forwards; }
    @keyframes flyInBlocked { 0% { left: -50px; opacity: 1; transform: rotate(0deg); } 60% { left: calc(100% - 150px); opacity: 1; transform: rotate(0deg); } 100% { left: calc(100% - 150px); opacity: 0; transform: rotate(180deg) scale(0); } }
    
    .impact { position: absolute; width: 60px; height: 60px; background: radial-gradient(circle, rgba(255,215,0,0.8) 0%, transparent 70%); border-radius: 50%; animation: impactBurst 0.4s ease forwards; pointer-events: none; z-index: 6; }
    @keyframes impactBurst { 0% { transform: translate(-50%, -50%) scale(0); opacity: 1; } 100% { transform: translate(-50%, -50%) scale(2); opacity: 0; } }
    
    .stats-panel { background: rgba(10, 10, 30, 0.9); border: var(--pixel-size) solid var(--gold); display: flex; flex-direction: column; gap: 0.5rem; padding: 0.5rem; }
    .stat-card { background: rgba(0,0,0,0.5); border: 2px solid var(--steel); padding: 0.6rem; }
    .stat-label { font-size: 0.4rem; color: #888; margin-bottom: 0.3rem; }
    .stat-value { font-size: 0.8rem; color: var(--gold); }
    .stat-bar { height: 12px; background: #1a1a2a; border: 2px solid var(--steel); margin-top: 0.3rem; overflow: hidden; }
    .stat-bar-fill { height: 100%; background: linear-gradient(90deg, var(--green) 0%, var(--gold) 100%); transition: width 0.5s ease; }
    
    .rules-section { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
    .rules-list { flex: 1; overflow-y: auto; padding: 0.3rem; }
    .rule-item { display: flex; align-items: center; gap: 0.3rem; padding: 0.3rem; margin: 0.2rem 0; font-size: 0.35rem; background: rgba(0,0,0,0.3); border-left: 3px solid var(--purple); }
    .rule-item.active { border-left-color: var(--green); background: rgba(34, 197, 94, 0.1); }
    .rule-status { width: 8px; height: 8px; }
    .rule-status.active { background: var(--green); }
    .rule-status.shadow { background: var(--purple); }
    .rule-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .rule-hits { color: var(--gold); font-size: 0.4rem; }
    
    .upgrade-effect { position: fixed; inset: 0; background: radial-gradient(circle at center, rgba(255,215,0,0.3) 0%, transparent 70%); pointer-events: none; opacity: 0; z-index: 200; }
    .upgrade-effect.active { animation: upgradeFlash 1s ease; }
    @keyframes upgradeFlash { 0% { opacity: 0; } 20% { opacity: 1; } 100% { opacity: 0; } }
    .upgrade-text { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 1.5rem; color: var(--gold); text-shadow: 0 0 20px var(--gold); opacity: 0; pointer-events: none; z-index: 201; }
    .upgrade-text.active { animation: upgradeTextPop 1.5s ease; }
    @keyframes upgradeTextPop { 0% { opacity: 0; transform: translate(-50%, -50%) scale(0.5); } 20% { opacity: 1; transform: translate(-50%, -50%) scale(1.2); } 40% { transform: translate(-50%, -50%) scale(1); } 80% { opacity: 1; } 100% { opacity: 0; transform: translate(-50%, -100%) scale(1); } }
    
    .footer { position: fixed; bottom: 0; left: 0; right: 0; background: rgba(10, 10, 30, 0.95); border-top: var(--pixel-size) solid var(--gold); padding: 0.5rem 1rem; display: flex; justify-content: space-around; font-size: 0.4rem; }
    .footer-stat { display: flex; align-items: center; gap: 0.5rem; }
    .footer-stat .label { color: #888; }
    .footer-stat .value { color: var(--gold); }
    
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #050510; }
    ::-webkit-scrollbar-thumb { background: var(--steel); }
    ::-webkit-scrollbar-thumb:hover { background: var(--gold); }
  </style>
</head>
<body>
  <header class="header">
    <div class="title">⚔ CLAWARMOR DEFENSE SYSTEM ⚔</div>
    <div class="status-indicator">
      <div class="status-dot" id="statusDot"></div>
      <span id="statusText">CONNECTING...</span>
    </div>
  </header>
  
  <div class="main-container">
    <div class="attack-panel">
      <div class="panel-title">📡 INCOMING ATTACKS</div>
      <div class="attack-list" id="attackList">
        <div class="attack-item"><span class="attack-icon">⏳</span><span class="attack-text">Waiting for events...</span></div>
      </div>
    </div>
    
    <div class="battlefield" id="battlefield">
      <div class="armor-wrapper">
        <div class="armor level-1" id="armor">
          <div class="armor-head"><div class="armor-visor"></div></div>
          <div class="armor-torso"><div class="armor-core"></div></div>
          <div class="armor-arm left"></div>
          <div class="armor-arm right"></div>
          <div class="armor-leg left"></div>
          <div class="armor-leg right"></div>
          <div class="armor-level" id="armorLevel">LV.1 BASIC</div>
          <div class="shield-effect" id="shieldEffect"></div>
        </div>
      </div>
    </div>
    
    <div class="stats-panel">
      <div class="stat-card">
        <div class="stat-label">DEFENSE RATING</div>
        <div class="stat-value" id="defenseRating">0</div>
        <div class="stat-bar"><div class="stat-bar-fill" id="defenseBar" style="width: 0%"></div></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">THRESHOLD</div>
        <div class="stat-value" id="thresholdValue">0.800</div>
        <div class="stat-bar"><div class="stat-bar-fill" id="thresholdBar" style="width: 80%"></div></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">TOTAL EVENTS</div>
        <div class="stat-value" id="totalEvents">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">BLOCKED</div>
        <div class="stat-value" id="blockedCount">0</div>
      </div>
      <div class="stat-card rules-section">
        <div class="stat-label">EVOLVED RULES</div>
        <div class="rules-list" id="rulesList"><div style="color:#666; padding:0.5rem; font-size:0.35rem;">Loading...</div></div>
      </div>
    </div>
  </div>
  
  <div class="upgrade-effect" id="upgradeEffect"></div>
  <div class="upgrade-text" id="upgradeText">ARMOR UPGRADED!</div>
  
  <div class="footer">
    <div class="footer-stat"><span class="label">ACTIVE RULES:</span><span class="value" id="activeRulesCount">0</span></div>
    <div class="footer-stat"><span class="label">SHADOW RULES:</span><span class="value" id="shadowRulesCount">0</span></div>
    <div class="footer-stat"><span class="label">LAST EVOLUTION:</span><span class="value" id="lastEvolution">--:--:--</span></div>
  </div>
  
  <script>
    const attackList = document.getElementById('attackList');
    const battlefield = document.getElementById('battlefield');
    const armor = document.getElementById('armor');
    const shieldEffect = document.getElementById('shieldEffect');
    const upgradeEffect = document.getElementById('upgradeEffect');
    const upgradeText = document.getElementById('upgradeText');
    
    let currentArmorLevel = 1;
    let lastRuleCount = 0;
    let processedLogs = new Set();
    const MAX_ATTACKS = 50;
    const projectileIcons = ['🔴', '⚡', '💀', '🎯', '⚔️', '🗡️'];
    
    function getArmorLevel(active, shadow) {
      const total = active + shadow;
      if (total >= 20) return 5;
      if (total >= 15) return 4;
      if (total >= 10) return 3;
      if (total >= 5) return 2;
      return 1;
    }
    
    function getLevelName(level) {
      return ['', 'BASIC', 'ENHANCED', 'ADVANCED', 'ELITE', 'LEGENDARY'][level] || 'BASIC';
    }
    
    function updateArmor(active, shadow) {
      const newLevel = getArmorLevel(active, shadow);
      if (newLevel > currentArmorLevel) {
        upgradeEffect.classList.add('active');
        upgradeText.classList.add('active');
        setTimeout(() => { upgradeEffect.classList.remove('active'); upgradeText.classList.remove('active'); }, 1500);
      }
      currentArmorLevel = newLevel;
      armor.className = 'armor level-' + newLevel;
      document.getElementById('armorLevel').textContent = 'LV.' + newLevel + ' ' + getLevelName(newLevel);
      document.getElementById('defenseRating').textContent = (active * 10 + shadow * 2);
      document.getElementById('defenseBar').style.width = Math.min(100, (active + shadow) * 5) + '%';
    }
    
    function addAttack(log, animate) {
      const text = log.text || log;
      let type = 'normal';
      let icon = '📨';
      
      if (text.includes('[EVOLVE-SHADOW]')) { type = 'shadow'; icon = '🟣'; }
      else if (text.includes('[EVOLVE-ACTIVE]')) { type = 'blocked'; icon = '🛡️'; }
      else if (text.includes('Promoted')) { type = 'evolve'; icon = '⬆️'; }
      else if (text.includes('evolution cycle')) { type = 'evolve'; icon = '🔄'; }
      else if (text.includes('WARN') || text.includes('risk=')) { type = 'blocked'; icon = '⚠️'; }
      
      const item = document.createElement('div');
      item.className = 'attack-item ' + type;
      const shortText = text.replace(/^\\d{4}-\\d{2}-\\d{2}T[\\d:.+]+\\s*/, '').substring(0, 80);
      item.innerHTML = '<span class="attack-icon">' + icon + '</span><span class="attack-text">' + shortText + '</span>';
      
      if (attackList.firstChild && attackList.firstChild.textContent.includes('Waiting')) {
        attackList.innerHTML = '';
      }
      attackList.insertBefore(item, attackList.firstChild);
      while (attackList.children.length > MAX_ATTACKS) attackList.removeChild(attackList.lastChild);
      
      if (animate && (type === 'blocked' || type === 'shadow')) {
        createProjectile(type === 'blocked');
      }
      if (text.includes('evolution cycle') || text.includes('Promoted')) {
        document.getElementById('lastEvolution').textContent = new Date().toLocaleTimeString();
      }
    }
    
    function createProjectile(blocked) {
      const p = document.createElement('div');
      p.className = 'projectile' + (blocked ? ' blocked' : '');
      p.textContent = projectileIcons[Math.floor(Math.random() * projectileIcons.length)];
      const topPos = 20 + Math.random() * 50;
      p.style.top = topPos + '%';
      battlefield.appendChild(p);
      
      if (blocked) {
        setTimeout(() => {
          shieldEffect.classList.add('active');
          setTimeout(() => shieldEffect.classList.remove('active'), 500);
          const impact = document.createElement('div');
          impact.className = 'impact';
          impact.style.left = 'calc(100% - 100px)';
          impact.style.top = topPos + '%';
          battlefield.appendChild(impact);
          setTimeout(() => impact.remove(), 400);
        }, 350);
      }
      setTimeout(() => p.remove(), 1000);
    }
    
    function updateStats(stats) {
      document.getElementById('totalEvents').textContent = stats.totalEvents || 0;
      document.getElementById('blockedCount').textContent = stats.blockedCount || 0;
      document.getElementById('activeRulesCount').textContent = stats.activeRules || 0;
      document.getElementById('shadowRulesCount').textContent = stats.shadowRules || 0;
      const threshold = stats.threshold || 0.8;
      document.getElementById('thresholdValue').textContent = threshold.toFixed(3);
      document.getElementById('thresholdBar').style.width = (threshold * 100) + '%';
      updateArmor(stats.activeRules || 0, stats.shadowRules || 0);
    }
    
    function updateRules(rules) {
      const container = document.getElementById('rulesList');
      if (!rules || rules.length === 0) {
        container.innerHTML = '<div style="color:#666; padding:0.5rem; font-size:0.35rem;">No rules yet</div>';
        return;
      }
      container.innerHTML = rules.slice(0, 15).map(r => 
        '<div class="rule-item ' + r.status + '"><div class="rule-status ' + r.status + '"></div><span class="rule-name">' + r.title + '</span><span class="rule-hits">' + r.hitCount + '</span></div>'
      ).join('');
    }
    
    function connect() {
      fetch('/api/logs?limit=50').then(r => r.json()).then(logs => {
        attackList.innerHTML = '';
        logs.forEach(l => { processedLogs.add(l.text); addAttack(l, false); });
        startPolling();
      }).catch(() => startPolling());
    }
    
    function startPolling() {
      document.getElementById('statusDot').classList.remove('offline');
      document.getElementById('statusText').textContent = 'ONLINE';
      
      fetch('/api/stats').then(r => r.json()).then(updateStats).catch(() => {});
      fetch('/api/rules').then(r => r.json()).then(updateRules).catch(() => {});
      
      setInterval(() => fetch('/api/stats').then(r => r.json()).then(updateStats).catch(() => {}), 3000);
      setInterval(() => fetch('/api/rules').then(r => r.json()).then(updateRules).catch(() => {}), 3000);
      setInterval(() => fetch('/api/logs?limit=30').then(r => r.json()).then(logs => {
        logs.forEach(l => {
          if (!processedLogs.has(l.text)) {
            processedLogs.add(l.text);
            addAttack(l, true);
          }
        });
      }).catch(() => {}), 2000);
    }
    
    connect();
  </script>
</body>
</html>`;
