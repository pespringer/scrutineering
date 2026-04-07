import http from "node:http";
import { createRemediationPlan } from "./remediation-planner.mjs";
import { createPullRequestArtifacts } from "../pr-generator/pr-generator.mjs";
import { evaluateCiChecks } from "../ci/ci-integration.mjs";
import { evaluateRolloutDecision } from "../rollout/staged-rollout.mjs";

const host = process.env.PLANNER_HOST || "127.0.0.1";
const port = Number(process.env.PLANNER_PORT || 8787);

function sendJson(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function collectBody(req) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    req.on("data", (chunk) => {
      buffer += chunk;
      if (buffer.length > 2_000_000) {
        reject(new Error("request_too_large"));
      }
    });
    req.on("end", () => resolve(buffer));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, { status: "ok" });
  }

  if (
    req.method !== "POST" ||
    !["/v1/plans", "/v1/pull-requests", "/v1/ci/checks", "/v1/rollout/evaluate"].includes(req.url)
  ) {
    return sendJson(res, 404, { error: "not_found" });
  }

  try {
    const payload = JSON.parse(await collectBody(req));
    if (req.url === "/v1/plans") {
      if (!Array.isArray(payload.findings)) {
        return sendJson(res, 400, {
          error: "invalid_request",
          message: "Expected body.findings to be an array.",
        });
      }

      const plan = createRemediationPlan(payload, { dryRun: Boolean(payload.dryRun) });
      return sendJson(res, 200, plan);
    }

    if (req.url === "/v1/pull-requests") {
      const result = createPullRequestArtifacts(payload);
      if (result.status === "failed") {
        return sendJson(res, 400, result);
      }

      return sendJson(res, 200, result);
    }

    if (req.url === "/v1/ci/checks") {
      const ciDecision = evaluateCiChecks(payload);
      return sendJson(res, 200, ciDecision);
    }

    const rolloutDecision = evaluateRolloutDecision(payload);
    return sendJson(res, 200, rolloutDecision);
  } catch (error) {
    return sendJson(res, 400, {
      error: "invalid_json",
      message: error.message,
    });
  }
});

server.listen(port, host, () => {
  console.log(`planner-service listening on http://${host}:${port}`);
});
