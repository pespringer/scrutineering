# Scrutineering Documentation

These pages describe the current system. [RESET-PLAN.md](RESET-PLAN.md) records
the completed reset; features come back under its Phase 6, each starting from a
design note in [design/](design/).

## Product
- [design/](design/README.md): design notes for Phase 6 features, written before the code
- [PRD.md](PRD.md): original product requirements (April 2026)
- [adr/0001-automatic-remediation-architecture.md](adr/0001-automatic-remediation-architecture.md): original architecture decision (superseded)

## API
- [api/application.md](api/application.md): the composed FastAPI app, health, readiness and metrics
- [api/dashboard-v1.md](api/dashboard-v1.md): every `/api/dashboard` route, with required roles

## Operating the stack
- [ARCHITECTURE.md](ARCHITECTURE.md): the services, the loop, the data model and the state machines
- [CONFIGURATION.md](CONFIGURATION.md): every environment variable, generated from `src/config.py`
- [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md): the workflow from pushing an image to a verified fix, and troubleshooting
- [operations/dashboard.md](operations/dashboard.md): building, configuring and smoke-testing the dashboard

## Remediation
- [operations/remediation-execution.md](operations/remediation-execution.md): sources, fix strategies, building and verifying candidates
- [operations/github-publication.md](operations/github-publication.md): publishing a verified fix as a GitHub pull request, and the merge webhook
