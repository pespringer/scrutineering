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

This is execution evidence, not a restore proof. A restore must still target
an isolated database and pass the documented restore preflight before it can
be treated as a recovery gate.
