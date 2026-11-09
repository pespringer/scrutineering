import assert from "node:assert/strict";
import test from "node:test";
import { createDistributedRateLimiter } from "./distributed-rate-limit.mjs";

test("distributed limiter shares counts through its atomic store callback", async () => {
  const counts = new Map();
  const increment = async (key) => {
    const next = (counts.get(key) || 0) + 1;
    counts.set(key, next);
    return next;
  };
  const first = createDistributedRateLimiter({ limitPerMinute: 1, increment });
  const second = createDistributedRateLimiter({ limitPerMinute: 1, increment });
  assert.equal((await first("same-client")).allowed, true);
  assert.equal((await second("same-client")).allowed, false);
});

test("rejects unsafe limiter keys", async () => {
  const limiter = createDistributedRateLimiter({ limitPerMinute: 1, increment: async () => 1 });
  await assert.rejects(() => limiter("bad key"), /invalid/);
});
