import http from "node:http";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRemediationPlan } from "./remediation-planner.mjs";
import { createPullRequestArtifacts } from "../pr-generator/pr-generator.mjs";
import { evaluateCiChecks } from "../ci/ci-integration.mjs";
import { evaluateRolloutDecision } from "../rollout/staged-rollout.mjs";
import { validatePlannerRequest } from "./contracts.mjs";

const host = process.env.PLANNER_HOST || "127.0.0.1";
const port = Number(process.env.PLANNER_PORT || 8787);

function sendJson(res, status, body, requestId) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Request-ID": requestId,
  });
  res.end(JSON.stringify(body));
}

function sendError(res, status, code, message, requestId, details = undefined) {
  const error = { code, message, requestId };
  if (details !== undefined) error.details = details;
  return sendJson(res, status, { error }, requestId);
}

function requestIdFor(req) {
  const supplied = req.headers["x-request-id"];
  if (typeof supplied === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(supplied)) {
    return supplied;
  }
  return randomUUID();
}

function createRateLimiter(limitPerMinute) {
  const windowMs = 60_000;
  const clients = new Map();

  return (clientKey) => {
    const now = Date.now();
    const current = clients.get(clientKey);
    const window = current && now - current.startedAt < windowMs
      ? current
      : { startedAt: now, count: 0 };

    window.count += 1;
    clients.set(clientKey, window);

    if (clients.size > 10_000) {
      for (const [key, value] of clients) {
        if (now - value.startedAt >= windowMs) clients.delete(key);
      }
    }

    return {
      allowed: window.count <= limitPerMinute,
      remaining: Math.max(0, limitPerMinute - window.count),
      retryAfterSeconds: Math.max(1, Math.ceil((window.startedAt + windowMs - now) / 1000)),
    };
  };
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
  rateLimitPerMinute = Number(process.env.PLANNER_RATE_LIMIT_PER_MINUTE || 60),
} = {}) {
  if (!isLoopbackHost(bindHost) && !apiKey) {
    throw new Error("PLANNER_API_KEY must be configured for non-loopback deployments");
  }
  if (!Number.isInteger(rateLimitPerMinute) || rateLimitPerMinute < 1) {
    throw new Error("PLANNER_RATE_LIMIT_PER_MINUTE must be a positive integer");
  }

  const consumeRateLimit = createRateLimiter(rateLimitPerMinute);

  return http.createServer(async (req, res) => {
    const requestId = requestIdFor(req);
    const requestPath = new URL(req.url || "/", "http://planner.local").pathname;

    if (req.method === "GET" && requestPath === "/health") {
      return sendJson(res, 200, { status: "ok" }, requestId);
    }

    const rate = consumeRateLimit(req.socket.remoteAddress || "unknown");
    res.setHeader("X-RateLimit-Limit", String(rateLimitPerMinute));
    res.setHeader("X-RateLimit-Remaining", String(rate.remaining));
    if (!rate.allowed) {
      res.setHeader("Retry-After", String(rate.retryAfterSeconds));
      return sendError(res, 429, "rate_limited", "Too many requests; retry later.", requestId);
    }

    if (!isAuthorized(req, apiKey)) {
      res.setHeader("WWW-Authenticate", "Bearer");
      return sendError(res, 401, "unauthorized", "Authentication is required.", requestId);
    }

    if (
      req.method !== "POST" ||
      !["/v1/plans", "/v1/pull-requests", "/v1/ci/checks", "/v1/rollout/evaluate"].includes(requestPath)
    ) {
      return sendError(res, 404, "not_found", "The requested route does not exist.", requestId);
    }

    try {
      const payload = JSON.parse(await collectBody(req));
      const validation = validatePlannerRequest(requestPath, payload);
      if (!validation.valid) {
        return sendError(res, 400, "invalid_request", validation.message, requestId);
      }
      if (requestPath === "/v1/plans") {
        const plan = createRemediationPlan(payload, { dryRun: Boolean(payload.dryRun) });
        return sendJson(res, 200, plan, requestId);
      }

      if (requestPath === "/v1/pull-requests") {
        const result = createPullRequestArtifacts(payload);
        if (result.status === "failed") {
          return sendError(
            res,
            400,
            "pr_generation_failed",
            "Pull request artifact generation failed.",
            requestId,
            result,
          );
        }

        return sendJson(res, 200, result, requestId);
      }

      if (requestPath === "/v1/ci/checks") {
        const ciDecision = evaluateCiChecks(payload);
        return sendJson(res, 200, ciDecision, requestId);
      }

      const rolloutDecision = evaluateRolloutDecision(payload);
      return sendJson(res, 200, rolloutDecision, requestId);
    } catch (error) {
      if (error.message === "request_too_large") {
        return sendError(res, 413, "request_too_large", "Request body exceeds the 2 MB limit.", requestId);
      }

      return sendError(res, 400, "invalid_json", "Request body must be valid JSON.", requestId);
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
