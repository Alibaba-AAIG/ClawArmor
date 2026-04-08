/**
 * Defense Event Store
 * JSON file-based persistent storage for defense events
 * Ported from ClawArmor Python implementation
 * Note: Using JSON files instead of SQLite for better compatibility in plugin environment
 */

import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { DefenseEvent, DefenseMetrics } from './types';
import { logger } from '../utils';

interface EventStoreData {
  events: DefenseEvent[];
  lastTriggeredCount: number;
  version: number;
}

export class DefenseEventStore {
  private dbPath: string;
  private statePath: string;
  private initialized: boolean = false;
  private cache: EventStoreData = { events: [], lastTriggeredCount: 0, version: 1 };
  private maxCacheSize: number = 1000; // Keep last 1000 events in memory

  constructor(dbPath: string) {
    // Expand ~ to home directory
    this.dbPath = dbPath.startsWith('~') 
      ? path.join(os.homedir(), dbPath.slice(1))
      : dbPath;
    this.statePath = this.dbPath.replace('.db', '_state.json');
  }

  /**
   * Initialize storage
   */
  async init(): Promise<void> {
    if (this.initialized) return;

    // Ensure directory exists
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Load existing data if available
    await this.load();

    this.initialized = true;
    logger.info(`[EventStore] Storage initialized at ${this.dbPath}`);
  }

  /**
   * Load data from disk
   */
  private async load(): Promise<void> {
    try {
      if (fs.existsSync(this.dbPath)) {
        const data = fs.readFileSync(this.dbPath, 'utf-8');
        const parsed = JSON.parse(data) as EventStoreData;
        this.cache = {
          events: parsed.events || [],
          lastTriggeredCount: parsed.lastTriggeredCount || 0,
          version: parsed.version || 1
        };
      }
    } catch (err) {
      logger.warn(`[EventStore] Failed to load data: ${err}`);
      this.cache = { events: [], lastTriggeredCount: 0, version: 1 };
    }
  }

  /**
   * Save data to disk
   */
  private async save(): Promise<void> {
    try {
      fs.writeFileSync(this.dbPath, JSON.stringify(this.cache, null, 2));
    } catch (err) {
      logger.error(`[EventStore] Failed to save data: ${err}`);
    }
  }

  /**
   * Record a defense event
   */
  async record(event: DefenseEvent): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }

    this.cache.events.unshift(event);
    
    // Trim cache if too large
    if (this.cache.events.length > this.maxCacheSize) {
      this.cache.events = this.cache.events.slice(0, this.maxCacheSize);
    }

    await this.save();
  }

  /**
   * Get total event count
   */
  async count(): Promise<number> {
    if (!this.initialized) {
      await this.init();
    }
    return this.cache.events.length;
  }

  /**
   * Get recent events
   */
  async getRecent(limit: number = 100): Promise<DefenseEvent[]> {
    if (!this.initialized) {
      await this.init();
    }
    return this.cache.events.slice(0, limit);
  }

  /**
   * Get events since a specific timestamp
   */
  async getSince(timestamp: number): Promise<DefenseEvent[]> {
    if (!this.initialized) {
      await this.init();
    }
    return this.cache.events.filter(e => e.timestamp > timestamp);
  }

  /**
   * Get all events
   */
  async getAll(): Promise<DefenseEvent[]> {
    if (!this.initialized) {
      await this.init();
    }
    return [...this.cache.events];
  }

  /**
   * Mark events as missed attacks (false negatives)
   */
  async markMissedAttack(eventIds: string[]): Promise<void> {
    if (!this.initialized || eventIds.length === 0) return;

    let modified = false;
    for (const event of this.cache.events) {
      if (eventIds.includes(event.id)) {
        event.missedAttack = true;
        modified = true;
      }
    }

    if (modified) {
      await this.save();
    }
  }

  /**
   * Mark events as false positives
   */
  async markFalsePositive(eventIds: string[]): Promise<void> {
    if (!this.initialized || eventIds.length === 0) return;

    let modified = false;
    for (const event of this.cache.events) {
      if (eventIds.includes(event.id)) {
        event.falsePositive = true;
        modified = true;
      }
    }

    if (modified) {
      await this.save();
    }
  }

  /**
   * Get defense metrics
   */
  async getMetrics(): Promise<DefenseMetrics> {
    if (!this.initialized) {
      await this.init();
    }

    const events = this.cache.events;
    const totalEvents = events.length;
    const blockedCount = events.filter(e => e.blocked).length;
    const falsePositives = events.filter(e => e.falsePositive).length;
    const falseNegatives = events.filter(e => e.missedAttack).length;

    const fpRate = totalEvents > 0 ? falsePositives / totalEvents : 0;
    const fnRate = totalEvents > 0 ? falseNegatives / totalEvents : 0;

    return {
      totalEvents,
      blockedCount,
      falsePositives,
      falseNegatives,
      fpRate,
      fnRate,
      activeRulesCount: 0,  // Will be filled by RuleBank
      shadowRulesCount: 0   // Will be filled by RuleBank
    };
  }

  /**
   * Get last triggered count for evolution tracking
   */
  async getLastTriggeredCount(): Promise<number> {
    if (!this.initialized) {
      await this.init();
    }
    return this.cache.lastTriggeredCount;
  }

  /**
   * Set last triggered count
   */
  async setLastTriggeredCount(count: number): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }
    this.cache.lastTriggeredCount = count;
    await this.save();
  }

  /**
   * Get events marked as missed attacks
   */
  async getMissedAttacks(): Promise<DefenseEvent[]> {
    if (!this.initialized) {
      await this.init();
    }
    return this.cache.events.filter(e => e.missedAttack);
  }

  /**
   * Get events marked as false positives
   */
  async getFalsePositives(): Promise<DefenseEvent[]> {
    if (!this.initialized) {
      await this.init();
    }
    return this.cache.events.filter(e => e.falsePositive);
  }

  /**
   * Close storage (no-op for file-based storage)
   */
  async close(): Promise<void> {
    if (this.initialized) {
      await this.save();
      this.initialized = false;
    }
  }
}
