import test from "node:test";
import assert from "node:assert/strict";
import { createRedisClient } from "./redis-client.mjs";

test("starts, health-checks, and stops one Redis client lifecycle", async () => {
  let connects = 0; let disconnects = 0;
  const lifecycle = createRedisClient({ connect: async () => { connects += 1; return {}; }, disconnect: async () => { disconnects += 1; }, ping: async () => "PONG" });
  await lifecycle.start(); await lifecycle.start();
  assert.equal(connects, 1); assert.equal(lifecycle.connected, true);
  await lifecycle.stop(); assert.equal(disconnects, 1); assert.equal(lifecycle.connected, false);
});

test("drops an unhealthy client after a failed health check", async () => {
  const lifecycle = createRedisClient({ connect: async () => ({}), ping: async () => { throw new Error("down"); } });
  await assert.rejects(() => lifecycle.start(), /down/);
  assert.equal(lifecycle.connected, false);
});

test("coalesces concurrent starts", async () => {
  let connects = 0;
  const lifecycle = createRedisClient({ connect: async () => { connects += 1; return {}; } });
  await Promise.all([lifecycle.start(), lifecycle.start()]);
  assert.equal(connects, 1);
});
