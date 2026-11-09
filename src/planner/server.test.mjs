import assert from "node:assert/strict";
import test from "node:test";
import { createPlannerServer } from "./server.mjs";

async function withServer(apiKey, callback) {
  const server = createPlannerServer({ apiKey, bindHost: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    return await callback(baseUrl);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test("health remains public while planner routes require an API key", async () => {
  await withServer("test-secret", async (baseUrl) => {
    const health = await fetch(`${baseUrl}/health`);
    assert.equal(health.status, 200);

    const unauthorized = await fetch(`${baseUrl}/v1/plans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ findings: [], dryRun: true }),
    });
    assert.equal(unauthorized.status, 401);
    assert.deepEqual(await unauthorized.json(), { error: "unauthorized" });

    const authorized = await fetch(`${baseUrl}/v1/plans`, {
      method: "POST",
      headers: {
        authorization: "Bearer test-secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({ findings: [], dryRun: true }),
    });
    assert.equal(authorized.status, 200);
    assert.equal((await authorized.json()).summary.totalFindings, 0);
  });
});

test("non-loopback planners fail closed without credentials", () => {
  assert.throws(
    () => createPlannerServer({ apiKey: "", bindHost: "0.0.0.0" }),
    /PLANNER_API_KEY must be configured/,
  );
});
