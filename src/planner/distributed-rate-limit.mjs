/**
 * Distributed limiter adapter contract. `increment` must be backed by an
 * atomic INCR + EXPIRE operation (for example, a Redis Lua script).
 */
export function createDistributedRateLimiter({ limitPerMinute, increment }) {
  if (!Number.isInteger(limitPerMinute) || limitPerMinute < 1) {
    throw new Error("limitPerMinute must be a positive integer");
  }
  if (typeof increment !== "function") throw new TypeError("increment callback is required");
  const windowMs = 60_000;
  return async (clientKey) => {
    if (!/^[A-Za-z0-9._:@/-]{1,256}$/.test(String(clientKey))) throw new Error("invalid limiter client key");
    const now = Date.now();
    const windowStart = Math.floor(now / windowMs) * windowMs;
    const count = await increment(`planner:rate:${windowStart}:${clientKey}`, windowMs);
    return {
      allowed: count <= limitPerMinute,
      remaining: Math.max(0, limitPerMinute - count),
      retryAfterSeconds: Math.max(1, Math.ceil((windowStart + windowMs - now) / 1000)),
    };
  };
}
