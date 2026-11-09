import test from "node:test";
import assert from "node:assert/strict";
import { createConfiguredRateLimiter } from "./configured-rate-limit.mjs";

test("builds a rate limiter from validated Redis configuration", async () => {
  const values = new Map();
  const limiter = createConfiguredRateLimiter({ env: { REDIS_URL: "redis://redis:6379/0" }, limitPerMinute: 2, client: { async incr(k) { const n = (values.get(k) || 0) + 1; values.set(k, n); return n; }, async expire() {} } });
  assert.equal((await limiter("principal")).allowed, true);
});
