# Planner API v1

The planner exposes a small, versioned HTTP API for deterministic remediation decisions. It does not directly mutate repositories.

## Authentication and tracing

All `/v1/*` routes require `Authorization: Bearer $PLANNER_API_KEY` (or `X-API-Key`) when an API key is configured. Non-loopback deployments refuse to start without `PLANNER_API_KEY`. `GET /health` is unauthenticated.

Every response includes `X-Request-ID`. Clients may supply a safe value using the same header; otherwise the server generates a UUID. Include this ID in support tickets and audit records.

## Routes

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/v1/plans` | Build a deterministic remediation plan from `findings[]`. |
| `POST` | `/v1/pull-requests` | Produce guarded PR artifacts from a plan. |
| `POST` | `/v1/ci/checks` | Evaluate required CI checks. |
| `POST` | `/v1/rollout/evaluate` | Evaluate staged rollout controls. |

`/v1/plans` requires an array-valued `findings` property. Use `dryRun: true` when no write actions should be produced.

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
