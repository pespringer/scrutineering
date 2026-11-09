import assert from "node:assert/strict";
import test from "node:test";
import { loadRedisConfig } from "./redis-config.mjs";

test("loads redis and rediss URLs", () => {
  assert.equal(loadRedisConfig({ REDIS_URL: "redis://redis:6379/0" }).tls, false);
  assert.equal(loadRedisConfig({ REDIS_URL: "rediss://redis.example/0" }).tls, true);
});

test("rejects missing and insecure production configuration", () => {
  assert.throws(() => loadRedisConfig({}), /required/);
  assert.throws(() => loadRedisConfig({ REDIS_URL: "redis://localhost", NODE_ENV: "production" }), /localhost/);
});
