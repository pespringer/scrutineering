# Scrutineering Documentation

[RESET-PLAN.md](RESET-PLAN.md) is the current plan. Phase 5 replaces these pages
with a README, an architecture doc, an operator guide and a configuration
reference; until then, this is the set that describes the current system.

## Product
- [PRD.md](PRD.md): original product requirements (April 2026)
- [adr/0001-automatic-remediation-architecture.md](adr/0001-automatic-remediation-architecture.md): original architecture decision (superseded)

## API
- [api/application.md](api/application.md): the composed FastAPI app, health, readiness and metrics
- [api/dashboard-v1.md](api/dashboard-v1.md): every `/api/dashboard` route, with required roles

## Operating the stack
- [operations/product-coherence.md](operations/product-coherence.md): the operator workflow from scan to verified fix
- [operations/dashboard.md](operations/dashboard.md): building, configuring and smoke-testing the dashboard
- [operations/local-registry.md](operations/local-registry.md): pushing and scanning images in the built-in registry
- [operations/scan-queues.md](operations/scan-queues.md): scan priorities and the shared scanner cache
- [operations/runtime-discovery.md](operations/runtime-discovery.md): scanning images of running containers
- [operations/readiness.md](operations/readiness.md): health and readiness probes

## Remediation
- [operations/remediation-execution.md](operations/remediation-execution.md): sources, fix strategies, building and verifying candidates
- [operations/github-publication.md](operations/github-publication.md): GitHub PR publication
- [operations/gitlab-publication.md](operations/gitlab-publication.md): GitLab MR publication
- [operations/github-cloudflare-staging.md](operations/github-cloudflare-staging.md): testing GitHub webhooks against a local stack
