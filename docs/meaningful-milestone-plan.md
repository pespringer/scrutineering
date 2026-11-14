# Meaningful Product Milestone Plan

## Outcome

Reach a trustworthy home-lab milestone where Scrutineering authenticates
operators, scans real containers, tracks findings over time, recommends useful
fixes, and proves a fix through rescan. Commercial features such as billing,
compliance exports, and automatic merge remain out of scope.

## Current Status

Steps 1–8 are implemented and verified locally for the home-lab scope. The November 14, 2026
acceptance run completed the real scan and runtime-discovery paths, then used
the disposable source fixture to prove signed-evidence verification,
isolated exact-match remediation, ordered validation gates, and a clean
post-change rescan. Remediation guidance now exposes impact, package/CVE/file
coordinates, confidence, and the next operator action. See
[`docs/operations/milestone-acceptance.md`](operations/milestone-acceptance.md)
for commands, evidence, and limitations.

## Work Plan

1. **Close the dashboard identity boundary.** Strip caller-supplied identity
   headers unless the request carries the explicitly configured trusted-proxy
   secret. Add regression coverage and document the trust model.
2. **Add a real authentication boundary.** Support OIDC/forward-auth for the
   dashboard while retaining API-key bootstrap for local administration. Enforce
   viewer/operator/admin roles at every mutating route.
3. **Remove misleading production fallback data.** Seed data may remain for an
   explicit development mode, but production configuration must show a clear
   backend error instead of demo findings.
4. **Implement finding lifecycle.** Add resolved/reopened timestamps and state
   transitions, close findings absent from a completed rescan, and expose age
   and lifecycle state in the API and dashboard.
5. **Connect runtime discovery to scanning.** Reuse the existing Docker and
   containerd discovery paths, apply include/exclude policy, deduplicate by
   immutable image identity, and schedule scans through existing queues.
6. **Prove the remediation loop.** Run a real image through discovery, scan,
   finding persistence, advice, guarded patch/rebuild, rescan, and resolution.
7. **Improve remediation guidance.** Explain impact, affected package/file,
   available fixed version, confidence, and the exact next operator action.
8. **Run acceptance testing.** Validate the complete flow on the home lab,
   record evidence, document prerequisites, and update the release-readiness
   checklist with known limitations.

## Definition of Done

- Dashboard access is authenticated and role-aware.
- No production page silently renders seed data.
- A discovered container produces a persisted scan and visible findings.
- Findings close and reopen from subsequent scan results.
- At least one guarded remediation is verified by a clean rescan.
- The acceptance run and any remaining infrastructure-dependent checks are
  documented with reproducible commands.

## Execution Order

Complete steps 1–3 before exposing the dashboard beyond the local machine.
Then implement the finding lifecycle and discovery-to-scan path. The real
remediation loop and acceptance test are the milestone gate; operational and
commercial expansion follows afterward.
