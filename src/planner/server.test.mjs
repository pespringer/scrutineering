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
    assert.match(health.headers.get("x-request-id"), /^[0-9a-f-]{36}$/);

    const unauthorized = await fetch(`${baseUrl}/v1/plans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ findings: [], dryRun: true }),
    });
    assert.equal(unauthorized.status, 401);
    const unauthorizedBody = await unauthorized.json();
    assert.equal(unauthorizedBody.error.code, "unauthorized");
    assert.equal(unauthorizedBody.error.requestId, unauthorized.headers.get("x-request-id"));

    const authorized = await fetch(`${baseUrl}/v1/plans`, {
      method: "POST",
      headers: {
        authorization: "Bearer test-secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({ findings: [], dryRun: true }),
    });
    assert.equal(authorized.status, 200);
    assert.match(authorized.headers.get("x-request-id"), /^[0-9a-f-]{36}$/);
    assert.equal((await authorized.json()).summary.totalFindings, 0);
  });
});

test("propagates a safe caller request ID and uses a structured validation error", async () => {
  await withServer("test-secret", async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/plans`, {
      method: "POST",
      headers: {
        authorization: "Bearer test-secret",
        "content-type": "application/json",
        "x-request-id": "ci-run_123",
      },
      body: JSON.stringify({ findings: "not-an-array" }),
    });

    assert.equal(response.status, 400);
    assert.equal(response.headers.get("x-request-id"), "ci-run_123");
    assert.deepEqual(await response.json(), {
      error: {
        code: "invalid_request",
        message: "Expected body.findings to be an array.",
        requestId: "ci-run_123",
      },
    });
  });
});

test("non-loopback planners fail closed without credentials", () => {
  assert.throws(
    () => createPlannerServer({ apiKey: "", bindHost: "0.0.0.0" }),
    /PLANNER_API_KEY must be configured/,
  );
});

test("rate limits planner routes but never blocks health checks", async () => {
  const server = createPlannerServer({
    apiKey: "test-secret",
    bindHost: "127.0.0.1",
    rateLimitPerMinute: 1,
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    const first = await fetch(`${baseUrl}/v1/plans`, {
      method: "POST",
      headers: { authorization: "Bearer test-secret", "content-type": "application/json" },
      body: JSON.stringify({ findings: [], dryRun: true }),
    });
    assert.equal(first.status, 200);

    const limited = await fetch(`${baseUrl}/v1/plans`, {
      method: "POST",
      headers: { authorization: "Bearer test-secret", "content-type": "application/json" },
      body: JSON.stringify({ findings: [], dryRun: true }),
    });
    assert.equal(limited.status, 429);
    assert.equal((await limited.json()).error.code, "rate_limited");
    assert.ok(Number(limited.headers.get("retry-after")) >= 1);

    const health = await fetch(`${baseUrl}/health`);
    assert.equal(health.status, 200);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("enforces the v1 request contract across planner endpoints", async () => {
  await withServer("test-secret", async (baseUrl) => {
    for (const path of ["/v1/pull-requests", "/v1/ci/checks", "/v1/rollout/evaluate"]) {
      const response = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: { authorization: "Bearer test-secret", "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      assert.equal(response.status, 400);
      assert.equal((await response.json()).error.code, "invalid_request");
    }
  });
});

test("uses authenticated identity for rate-limit buckets", async () => {
  const server = createPlannerServer({ apiKey: "test-secret", bindHost: "127.0.0.1", rateLimitPerMinute: 1 });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const request = (key) => fetch(`${baseUrl}/v1/plans`, {
    method: "POST",
    headers: { "x-api-key": key, "content-type": "application/json" },
    body: JSON.stringify({ findings: [], dryRun: true }),
  });
  try {
    assert.equal((await request("test-secret")).status, 200);
    assert.equal((await request("test-secret")).status, 429);
    assert.equal((await request("another-key")).status, 401);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("enforces configured roles and tenant scopes", async () => {
  const server = createPlannerServer({
    bindHost: "127.0.0.1",
    apiKey: "",
    apiKeys: { ciKey: { id: "ci", roles: ["ci"], tenantIds: ["tenant-a"] } },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    const plans = await fetch(`${baseUrl}/v1/plans`, {
      method: "POST", headers: { "x-api-key": "ciKey", "content-type": "application/json" },
      body: JSON.stringify({ findings: [] }),
    });
    assert.equal(plans.status, 403);
    const checks = await fetch(`${baseUrl}/v1/ci/checks`, {
      method: "POST", headers: { "x-api-key": "ciKey", "content-type": "application/json" },
      body: JSON.stringify({ checks: [], tenantId: "tenant-b" }),
    });
    assert.equal(checks.status, 403);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
