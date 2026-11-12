# Recovery Go-Live Checklist

This checklist covers the receiver-independent controls. External alert
receiver delivery remains a separate operator gate.

- [ ] Run `npm run validate:migrations` and apply migrations to the target database.
- [ ] Run `npm run drill:staging-readiness` and `npm run drill:staging-recovery`.
- [ ] Confirm worker registration includes recovery, retention, and alert tasks.
- [ ] Confirm `REMEDIATION_ALERT_DELIVERY_ENABLED=false` until a receiver has been reviewed.
- [ ] Confirm evidence purge remains disabled and retention reports are archived.
- [ ] Verify provider credential diagnostics and rotation age.
- [ ] Verify recovery lease, provider failure, dead-letter, and escalation alerts.
- [ ] Review signed evidence and audit export verification results.
- [ ] Exercise rollback and recovery with the deterministic fixtures.
- [ ] Record the release commit, migration head, test results, and operator approval.

Local artifact checks:

```bash
npm run validate:migrations
npm run validate:release-package
npm run drill:staging-recovery
```
