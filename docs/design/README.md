# Design Notes

Each Phase 6 feature ([RESET-PLAN.md](../RESET-PLAN.md#phase-6--bring-back-one-at-a-time))
starts here: a short note, reviewed and merged before any code. When the feature
ships, the note is updated to match what was built, and the operator docs take
over the details.

A note answers:

- **Problem:** what the operator can't do today, in one paragraph.
- **Scope:** what's in, and what's explicitly out.
- **Design:** the data, the code paths, and how it fits the loop.
- **Configuration:** every new setting, with its default.
- **Security:** secrets, trust boundaries, and what an attacker gains.
- **Testing:** unit tests, and what the golden path checks.
- **Rollout:** the PRs, in order.
- **Open questions:** decisions for the reviewer.

## Notes

- [notifications.md](notifications.md): Slack and webhook notifications (built)
- [forward-auth.md](forward-auth.md): sign-in through a forward-auth proxy (OIDC) (built)
- [runtime-discovery.md](runtime-discovery.md): runtime discovery on by default (built)
- [sbom-evidence.md](sbom-evidence.md): signed SBOMs and remediation evidence (in progress: SBOMs and signing built)
