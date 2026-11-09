# Planner API v1

The planner exposes a small, versioned HTTP API for deterministic remediation decisions. It does not directly mutate repositories.

## Authentication and tracing

All `/v1/*` routes require `Authorization: Bearer $PLANNER_API_KEY` (or `X-API-Key`) when an API key is configured. Non-loopback deployments refuse to start without `PLANNER_API_KEY`. `GET /health` is unauthenticated.

Every response includes `X-Request-ID`. Clients may supply a safe value using the same header; otherwise the server generates a UUID. Include this ID in support tickets and audit records.

Non-health routes are rate-limited per authenticated credential (or client
address before authentication). The default is 60 requests per minute and can
be changed with `PLANNER_RATE_LIMIT_PER_MINUTE`.
This limiter is process-local; multi-replica deployments must add a shared
gateway or Redis-backed limiter before relying on the limit as a global policy.
The server accepts an injected async limiter; use
`createDistributedRateLimiter` with an atomic Redis `INCR`/`EXPIRE` adapter for
multi-replica deployments. `createRedisIncrement` supplies that adapter for a
node-redis-compatible client.
Production configuration must provide `REDIS_URL`; use `rediss://` when Redis
traffic crosses a trust boundary.

## Routes

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/v1/plans` | Build a deterministic remediation plan from `findings[]`. |
| `POST` | `/v1/pull-requests` | Produce guarded PR artifacts from a plan. |
| `POST` | `/v1/ci/checks` | Evaluate required CI checks. |
| `POST` | `/v1/rollout/evaluate` | Evaluate staged rollout controls. |

`/v1/plans` requires an array-valued `findings` property. Use `dryRun: true` when no write actions should be produced.

## Request contracts

All v1 bodies must be JSON objects. Required fields are:

- `/v1/plans`: `findings` array.
- `/v1/pull-requests`: non-empty `idempotencyKey` and `plan` object.
- `/v1/ci/checks`: `checks` array.
- `/v1/rollout/evaluate`: non-empty `teamId` and `riskLevel` strings.

Missing or incorrectly typed fields return the standard `invalid_request` envelope.

## Error envelope

Non-2xx responses use one shape:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Expected body.findings to be an array.",
    "requestId": "ci-run_123"
  }
}
```

Known codes include `unauthorized`, `not_found`, `invalid_request`, `invalid_json`, `request_too_large`, and `pr_generation_failed`. Clients should branch on `code`, not message text.
