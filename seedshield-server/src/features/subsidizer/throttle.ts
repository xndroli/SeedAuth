import { SeedShieldErrorCode } from "../../core/types.js";

/**
 * Throttle entry for a device.
 */
interface ThrottleEntry {
  transactionCount: number;
  lastReset: number;
}

/**
 * ThrottlePolicy handles Sybil-resistance by limiting the number of 
 * subsidized transactions per device within a rolling window.
 * 
 * TODO: For production, migrate memory-based limits to a persistent store 
 * like Redis to support horizontal scaling and durability across restarts.
 */
export class ThrottlePolicy {
  private readonly limits = new Map<string, ThrottleEntry>();
  private lastCleanup = Date.now();

  constructor(
    private readonly maxTransactions: number = 5,
    private readonly windowMs: number = 24 * 60 * 60 * 1000 // 24 hours
  ) {}

  /**
   * Checks if the device is allowed to perform a subsidized transaction.
   * Increments the counter if allowed.
   * 
   * @param deviceId The unique hardware-attested device ID.
   * @returns boolean true if allowed, false if throttled.
   */
  public checkAndIncrement(deviceId: string): boolean {
    const now = Date.now();
    
    // Periodic cleanup to prevent memory leaks (Finding 12)
    this.maybeCleanup(now);

    let entry = this.limits.get(deviceId);

    // Reset if window has passed or new device
    if (!entry || now - entry.lastReset > this.windowMs) {
      entry = { transactionCount: 0, lastReset: now };
    }

    if (entry.transactionCount >= this.maxTransactions) {
      return false;
    }

    entry.transactionCount += 1;
    this.limits.set(deviceId, entry);
    return true;
  }

  /**
   * Resets the throttle for a specific device (admin/recovery use).
   */
  public reset(deviceId: string): void {
    this.limits.delete(deviceId);
  }

  /**
   * Periodically removes expired entries from the map to prevent memory exhaustion.
   */
  private maybeCleanup(now: number): void {
    const cleanupInterval = 10 * 60 * 1000; // Fixed 10-minute cleanup interval (Finding 12)
    if (now - this.lastCleanup < cleanupInterval) return;

    for (const [deviceId, entry] of this.limits.entries()) {
      if (now - entry.lastReset > this.windowMs) {
        this.limits.delete(deviceId);
      }
    }
    this.lastCleanup = now;
  }
}
