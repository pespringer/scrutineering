import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileIdempotencyStore } from "./idempotency-store.mjs";

test("persists publication idempotency records", async () => {
  const store = createFileIdempotencyStore(join(await mkdtemp(join(tmpdir(), "scrutineering-")), "keys.json"));
  await store.set("repo:run", { number: 4 });
  assert.deepEqual(await store.get("repo:run"), { number: 4 });
});
