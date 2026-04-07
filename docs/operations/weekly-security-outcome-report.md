# Weekly Security Outcome Report

Generated at: 2026-04-05T07:00:00.000Z
Window: 2026-03-29T00:00:00.000Z -> 2026-04-05T00:00:00.000Z

## Executive Summary

- Total remediation runs: 4
- Success rate: 50.00%
- P95 latency: 90.00m
- Change-failure rate: 33.33%
- Vulnerability burn-down: 20.00% (14 resolved)
- SLO alerts this window: 3

## Dashboard View by Team

| Team | Runs | Success Rate | P95 Latency | Change Failure Rate | Net Vulnerability Delta |
|---|---:|---:|---:|---:|---:|
| payments | 2 | 50.00% | 90.00m | 50.00% | -3 |
| risk | 2 | 50.00% | 25.00m | 0.00% | -3 |

## Dashboard View by Repository

| Repository | Runs | Success Rate | P95 Latency | Change Failure Rate | Net Vulnerability Delta |
|---|---:|---:|---:|---:|---:|
| api | 2 | 50.00% | 90.00m | 50.00% | -3 |
| worker | 2 | 50.00% | 25.00m | 0.00% | -3 |

## SLO Status

| SLO | Target | Observed | Status |
|---|---|---|---|
| success_rate | >= 95% | 50.00% | breach |
| latency_p95 | <= 45m | 90.00m | breach |
| change_failure_rate | <= 8% | 33.33% | breach |
| vulnerability_burndown | >= 20% | 20.00% | pass |

## Alert Routing

- slo_success_rate_breach: Automated remediation success rate is out of SLO. -> owner=platform-remediation-owner, on-call=platform-security-oncall
- slo_latency_p95_breach: End-to-end remediation latency (P95) is out of SLO. -> owner=platform-remediation-owner, on-call=platform-security-oncall
- slo_change_failure_rate_breach: Post-merge remediation regressions is out of SLO. -> owner=platform-remediation-owner, on-call=platform-security-oncall
