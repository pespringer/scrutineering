# Remediation Lifecycle

Remediation records are advanced through an explicit fail-closed state graph:

```text
pending → analyzing → patching → building → verifying → pr_opened → completed
   └──────────────→ requires_review ────────┘
```

Any active state may move to `failed`; `pending` may move to `skipped`. The
`completed`, `failed`, and `skipped` states are terminal. A review decision can
resume through `requires_review → analyzing`.

Repository updates validate the current database state before writing a new
status. Callers must not update the status column directly. This prevents a
failed or completed remediation from being silently reopened and creates a
stable foundation for retry, approval, rollback, and post-merge verification.
