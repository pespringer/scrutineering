# Scan retention operations

Operations exposes a retention preview for completed scans older than
`SCAN_RETENTION_DAYS` (90 days by default). The preview reports eligible scan
and finding counts without changing data.

Operators may queue a dry-run report from the Operations page. A real purge
requires all of the following:

- `SCAN_PURGE_ENABLED=true` in the API and worker configuration.
- A security-operator or admin role.
- Explicit confirmation in the dashboard action.

The queue is bounded to 500 records by the dashboard and records an audit
event. The worker deletes the selected scan findings and scan rows only after
the task starts with `dry_run=false`; the existing policy still fails closed
when purge is disabled. Review the preview and backup freshness before
enabling destructive cleanup.
