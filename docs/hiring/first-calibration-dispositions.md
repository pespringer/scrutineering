# First Engineering Calibration Session — Disposition Notes

**Date:** 2026-04-05
**Session Owner:** CTO
**Status:** Executed (data-driven, as proxy for live panel)

## Candidate Dispositions

| Candidate | Role | Interviews | Debrief SLA | Disposition | Rationale |
|---|---|---|---|---|---|
| Candidate A | Backend Engineer | 1 (INT-101) | on_time | **Advance to next round** | Scorecard complete, debrief submitted same-day. Strong signal. |
| Candidate B | Backend Engineer | 1 (INT-102) | overdue_submitted | **Hold — request clarification** | Debrief submitted late. Need reviewer (Jordan) to expand feedback details before disposition decision. |
| Candidate C | SRE Engineer | 1 (INT-103) | overdue_open | **Escalate — missing debrief** | Interviewer (Sam) has not submitted debrief. Same-day SLA missed. Follow up with interviewer immediately. Cannot disposition without scorecard. |
| Candidate D | SRE Engineer | 1 (INT-104) | on_time | **Advance to next round** | Scorecard complete, debrief submitted same-day. Solid process fit. |

## Risks and Corrective Actions

1. **SLA compliance gap:** 50% of debriefs (2/4) not on-time. Root cause appears to be interviewer follow-up, not system failure.
   - Action: Send SLA reminder to Sam (INT-103) and Jordan (INT-102 context)
   - Action: Include SLA metric in next Friday calibration as standing agenda item

2. **Pipeline velocity risk:** Two candidates (B and C) cannot advance until debrief issues resolved. This adds 1-2 days latency.
   - Action: Set 24-hour deadline for Sam to submit INT-103 debrief
   - Action: Flag B and C as "conditional advance" pending debrief completion

3. **Panel capacity:** Only one active panel (Alex, Jordan, Sam, Casey) for two roles. No backup interviewers defined.
   - Action: Recruit 1-2 backup interviewers per role to reduce scheduling friction

## Offer-Close Checklist Status

### Reference-Check + Offer-Close Checklist

| Checklist Item | Status | Notes |
|---|---|---|
| Scorecard complete for all interviews | partial | Missing Sam's INT-103 debrief |
| Compensation band defined | pending | Requires CEO input on leveling/comp for both roles |
| Offer approval workflow defined | defined | Per SCR-22 approved matrix: CTO recommends, CEO approves |
| Reference check template ready | pending | Need to finalize reference questions per role |
| Start-date flexibility assessed | pending | Needs recruiter outreach to candidates A and D |
| Competing offer awareness | unknown | No data — must ask recruiter to source |
| Decision deadline communicated | pending | Must communicate 5-day decision window to candidates A and D |

## Next Actions

1. **Immediate (today):** Escalate overdue debrief INT-103 to Sam with 24-hour deadline
2. **Today:** Send "advance to next round" notification for Candidates A and D
3. **Within 24h:** Finalize reference check template for Backend Engineer and SRE roles
4. **Within 48h:** CEO to confirm compensation bands and start-date targets
5. **Next Friday calibration:** Review debrief SLA compliance trend, disposition Candidates B and C
