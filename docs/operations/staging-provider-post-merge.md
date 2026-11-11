# Staging Provider-to-Post-Merge Drill

Live provider publication remains disabled unless
`REMEDIATION_PUBLICATION_ENABLED=true` is explicitly configured. Run the
deterministic local preflight with:

```bash
npm run drill:staging-provider
```

For live staging, configure `GITHUB_WEBHOOK_SECRET` and/or
`GITLAB_WEBHOOK_SECRET` in the staging secret store. Register
`/api/dashboard/webhooks/{provider}` for merge-request events and send the
provider delivery ID plus its HMAC signature. GitHub may use
`x-hub-signature-256`; the normalized contract also accepts
`x-provider-signature`. GitLab delivery IDs are read from
`x-gitlab-event-uuid`.

Callbacks are accepted only after signature verification. Duplicate delivery
IDs are acknowledged without replaying the decision. A matched merge updates
the publication with its commit, deployed digest, scan status, and finding
delta. Digest drift, incomplete scans, or increased findings produce a durable
`rollback_required` event and a validated `git revert --no-edit` command; the
service does not execute that command automatically.

Before promotion, record the publication URL, callback ID, verification result,
scan evidence, and rollback decision. Confirm the remediation detail page and
`/api/dashboard/remediations/publications/reconciliation` agree with the
database. Rotate webhook secrets after the drill and verify old signatures are
rejected.
