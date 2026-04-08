/**
 * Logger for ClawArmor
 * Outputs to console (captured by OpenClaw gateway.log)
 */

const PREFIX = '[ClawArmor]';

export class Logger {
  private static instance: Logger;

  private constructor() {}

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  info(message: string): void {
    console.log(`${PREFIX} ${message}`);
  }

  warn(message: string): void {
    // Use console.warn to trigger OpenClaw WARN level
    console.warn(`${PREFIX} ${message}`);
  }

  error(message: string): void {
    // Use console.error to trigger OpenClaw ERROR level
    console.error(`${PREFIX} ${message}`);
  }

  debug(message: string): void {
    if (process.env.CLAWARMOR_DEBUG === 'true') {
      console.log(`${PREFIX} [DEBUG] ${message}`);
    }
  }
}

export const logger = Logger.getInstance();
