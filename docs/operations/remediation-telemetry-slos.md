# Remediation Telemetry and SLO Policy

- Owner: Founding Engineer (Platform)
- Last Updated: 2026-04-05
- Scope: End-to-end remediation telemetry, service-level indicators, and breach routing.

## Telemetry Metrics

The telemetry snapshot tracks the following core metrics for dashboarding by team and repository:

- End-to-end latency (`latencyP50Minutes`, `latencyP95Minutes`)
- Remediation success rate (`successRate`)
- Change-failure rate (`changeFailureRate`) for deployed remediation changes
- Vulnerability impact (`vulnerabilitiesResolved`, `vulnerabilitiesIntroduced`, `netVulnerabilityDelta`)
- Vulnerability burn-down (`startingOpen`, `endingOpen`, `resolved`, `burndownRate`)

## SLO Targets

- Success rate: `>= 97%`
- P95 latency: `<= 60 minutes`
- Change-failure rate: `<= 10%`
- Vulnerability burn-down rate: `>= 20%` per reporting window

All SLO targets are configurable in snapshot input (`sloTargets`) to allow team-specific tightening.

## Alert Routing

When an SLO is breached, the telemetry output emits explicit alert objects with routing metadata:

- `owner`: remediation owner queue
- `onCall`: security/platform on-call queue

Default route names:

- `security-platform-owner`
- `security-platform-oncall`

Route names can be overridden with `alertRouting` in snapshot input.

## Weekly Reporting Contract

Weekly reporting uses generated telemetry output to auto-populate:

- executive summary metrics
- dashboard slices by team and repository
- SLO pass/breach table
- owner/on-call routing details for active breaches

Generate weekly report artifact:

```bash
npm run report:security-outcomes
```
