import assert from "node:assert/strict";
import test from "node:test";
import { createRedisIncrement } from "./redis-rate-limit.mjs";

test("Redis adapter sets expiry only for a new rate-limit window", async () => {
  const counts = new Map();
  const expirations = [];
  const client = {
    async incr(key) { const count = (counts.get(key) || 0) + 1; counts.set(key, count); return count; },
    async expire(key, seconds) { expirations.push([key, seconds]); },
  };
  const increment = createRedisIncrement(client);
  assert.equal(await increment("key", 60_000), 1);
  assert.equal(await increment("key", 60_000), 2);
  assert.deepEqual(expirations, [["key", 60]]);
});
