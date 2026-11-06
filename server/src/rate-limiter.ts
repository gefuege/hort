import { DurableObject } from "cloudflare:workers";
import { fail } from "./http";

// Contract §5.1: [limit, window in seconds].
export const LIMITS = {
  create: [5, 3600], // account creations per IP
  slot: [10, 60], // slot fetches per IP and account
  write: [60, 60], // writes per device (or "ak") and account
} as const;

// Fixed-window counter, one instance per bucket and key. The key (which may
// contain an IP address) only selects the instance and is never stored; the
// alarm deletes the counter when its window ends.
export class RateLimiter extends DurableObject {
  // Returns 0 when the hit is allowed, otherwise the seconds until the window ends.
  hit(limit: number, windowSeconds: number): number {
    const now = Date.now();
    let w = this.ctx.storage.kv.get<{ start: number; count: number }>("w");
    if (!w || now >= w.start + windowSeconds * 1000) {
      w = { start: now, count: 0 };
      this.ctx.storage.setAlarm(now + windowSeconds * 1000);
    }
    if (w.count >= limit) return Math.max(1, Math.ceil((w.start + windowSeconds * 1000 - now) / 1000));
    w.count++;
    this.ctx.storage.kv.put("w", w);
    return 0;
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

export async function rateLimit(env: Env, bucket: keyof typeof LIMITS, key: string): Promise<Response | null> {
  const [limit, windowSeconds] = LIMITS[bucket];
  const stub = env.RATE_LIMITER.jurisdiction("eu").getByName(`${bucket}:${key}`);
  const retryAfter = await stub.hit(limit, windowSeconds);
  if (retryAfter === 0) return null;
  return fail(429, `rate limit exceeded; retry in ${retryAfter} s`, { "Retry-After": String(retryAfter) });
}
