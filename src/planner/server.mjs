import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRemediationPlan } from "./remediation-planner.mjs";
import { createPullRequestArtifacts } from "../pr-generator/pr-generator.mjs";
import { evaluateCiChecks } from "../ci/ci-integration.mjs";
import { evaluateRolloutDecision } from "../rollout/staged-rollout.mjs";

const host = process.env.PLANNER_HOST || "127.0.0.1";
const port = Number(process.env.PLANNER_PORT || 8787);

function sendJson(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
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

function isLoopbackHost(value) {
  return ["127.0.0.1", "::1", "localhost"].includes(value);
}

function isAuthorized(req, apiKey) {
  if (!apiKey) return true;
  const bearer = req.headers.authorization;
  const suppliedKey = req.headers["x-api-key"];
  return bearer === `Bearer ${apiKey}` || suppliedKey === apiKey;
}

export function createPlannerServer({
  apiKey = process.env.PLANNER_API_KEY || "",
  bindHost = host,
} = {}) {
  if (!isLoopbackHost(bindHost) && !apiKey) {
    throw new Error("PLANNER_API_KEY must be configured for non-loopback deployments");
  }

  return http.createServer(async (req, res) => {
    const requestPath = new URL(req.url || "/", "http://planner.local").pathname;

    if (req.method === "GET" && requestPath === "/health") {
      return sendJson(res, 200, { status: "ok" });
    }

    if (!isAuthorized(req, apiKey)) {
      res.setHeader("WWW-Authenticate", "Bearer");
      return sendJson(res, 401, { error: "unauthorized" });
    }

    if (
      req.method !== "POST" ||
      !["/v1/plans", "/v1/pull-requests", "/v1/ci/checks", "/v1/rollout/evaluate"].includes(requestPath)
    ) {
      return sendJson(res, 404, { error: "not_found" });
    }

    try {
      const payload = JSON.parse(await collectBody(req));
      if (requestPath === "/v1/plans") {
        if (!Array.isArray(payload.findings)) {
          return sendJson(res, 400, {
            error: "invalid_request",
            message: "Expected body.findings to be an array.",
          });
        }

        const plan = createRemediationPlan(payload, { dryRun: Boolean(payload.dryRun) });
        return sendJson(res, 200, plan);
      }

      if (requestPath === "/v1/pull-requests") {
        const result = createPullRequestArtifacts(payload);
        if (result.status === "failed") {
          return sendJson(res, 400, result);
        }

        return sendJson(res, 200, result);
      }

      if (requestPath === "/v1/ci/checks") {
        const ciDecision = evaluateCiChecks(payload);
        return sendJson(res, 200, ciDecision);
      }

      const rolloutDecision = evaluateRolloutDecision(payload);
      return sendJson(res, 200, rolloutDecision);
    } catch (error) {
      if (error.message === "request_too_large") {
        return sendJson(res, 413, { error: "request_too_large" });
      }

      return sendJson(res, 400, {
        error: "invalid_json",
        message: error.message,
      });
    }
  });
}

export function startPlannerServer({
  bindHost = host,
  bindPort = port,
  apiKey = process.env.PLANNER_API_KEY || "",
} = {}) {
  const server = createPlannerServer({ apiKey, bindHost });
  return server.listen(bindPort, bindHost, () => {
    console.log(`planner-service listening on http://${bindHost}:${bindPort}`);
  });
}

const entrypoint = process.argv[1] && path.resolve(process.argv[1]);
if (entrypoint === fileURLToPath(import.meta.url)) {
  startPlannerServer();
}
