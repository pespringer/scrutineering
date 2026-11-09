import { loadRedisConfig } from "./redis-config.mjs";
import { createDistributedRateLimiter } from "./distributed-rate-limit.mjs";
import { createRedisIncrement } from "./redis-rate-limit.mjs";

export function createConfiguredRateLimiter({ env = process.env, client, limitPerMinute } = {}) {
  loadRedisConfig(env);
  if (!client) throw new Error("connected Redis client is required");
  return createDistributedRateLimiter({ limitPerMinute, increment: createRedisIncrement(client) });
}
