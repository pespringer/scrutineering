# Dashboard API v1

The dashboard data boundary is mounted at `/api/dashboard` on the Python API.
All routes require `PYTHON_API_KEY`, service authentication, or a verified
trusted OIDC ingress identity.

## Read APIs

- `GET /posture/summary` — current open-finding counts and latest scan state.
- `GET /posture/trend?days=30` — severity snapshots for the selected window.
- `GET /scans?limit=20&offset=0&status=running&search=api` — paginated scan
  history.
- `GET /scans/{scan_id}` — durable scan status for polling.
- `GET /images?limit=20&offset=0&search=nginx&severity=high` — paginated image
  inventory.
- `GET /images/{image_id}?limit=25&offset=0&severity=critical` — image detail
  and paginated findings.
- `GET /session` — the mapped operator identity context.

Paginated responses use `{ items, limit, offset, count, total }`. The Next.js
dashboard proxy keeps API keys and the trusted proxy secret server-side.

## Scan controls

- `POST /scans` with `{ "image_name": "nginx:1.27", "priority": "normal" }`
  persists a pending scan and queues Celery work.
- `POST /scans/{scan_id}/cancel` revokes queued work and records `cancelled`.

For OIDC, an ingress must verify the token before forwarding
`x-authenticated-sub` and optional email/roles headers. The API accepts those
headers only when `x-dashboard-proxy-secret` matches the server-side
`DASHBOARD_TRUSTED_PROXY_SECRET`.
