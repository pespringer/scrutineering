# Backup Evidence

Scrutineering records backup artifact observations in `backup_executions` when
the scheduled freshness task reads `BACKUP_METADATA_PATH`. Each observation is
idempotent for an artifact name and creation timestamp and records its source,
age, size, verification state, and optional digest metadata. Artifact contents
are never returned by the dashboard API.

The operations page reads the same durable records when deciding whether the
backup check is fresh. The API endpoint is available to authenticated
operators at `GET /api/dashboard/backup-evidence`; the dashboard proxy exposes
`GET /api/backup-evidence`.

An administrator can explicitly request a PostgreSQL backup with
`POST /api/dashboard/backup-evidence/execute` and body `{"confirm": true}`.
Set `BACKUP_EXECUTION_ENABLED=true` only after reviewing the destination and
timeout settings. The worker writes a custom-format `pg_dump` artifact to the
dedicated backup volume, records its SHA-256 and size, and emits success or
failure audit evidence. The endpoint rejects requests without explicit
confirmation and is disabled by default.

Scheduled execution is also disabled by default. To opt in, set
`BACKUP_SCHEDULED_EXECUTION_ENABLED=true` and choose
`BACKUP_MIN_INTERVAL_SECONDS` (the default is 86400). Celery Beat evaluates
the durable latest verified artifact hourly and queues one backup only after
the freshness window is due. The queued execution, task ID, and result remain
in `BackupExecution` and the audit trail; failed executions do not make the
freshness gate pass.

## Restore verification

An operator can verify a stored artifact with
`POST /api/dashboard/backup-evidence/{id}/restore` and body
`{"confirm": true}`. This operation is disabled unless both
`BACKUP_RESTORE_ENABLED=true` and `BACKUP_RESTORE_TARGET_ISOLATED=true` are set.
The worker also requires `BACKUP_RESTORE_ADMIN_DATABASE_URL`, using a PostgreSQL
credential with `CREATEDB` permission. For each run it creates a uniquely named
temporary database, restores the custom-format dump with `pg_restore`, records
table and selected row counts, then drops the temporary database. A successful
run is only marked verified when cleanup succeeds; failure and cleanup evidence
are retained in `backup_restore_executions` and the audit log.

The target is intentionally disposable. Never point the admin URL at a
production credential or enable this operation without confirming that the
credential can create and drop isolated databases.

Metadata entries use this shape:

```json
[
  {
    "name": "scrutineering-2026-11-14.dump",
    "created_at": "2026-11-14T02:00:00+00:00",
    "size_bytes": 1048576,
    "verified": true
  }
]
```

Backup execution and restore verification are separate evidence records. A
fresh backup without a successful isolated restore remains insufficient for a
recovery gate.
