# Service Readiness

`GET /health` is a lightweight process liveness check. `GET /ready` executes a
database connectivity probe and returns `ready` or `not_ready`; Kubernetes and
Compose should use readiness for traffic gating and health for restart policy.
