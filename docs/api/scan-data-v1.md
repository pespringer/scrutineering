# Scan Data API v1

`src.scan.api.router` defines the shared read contract under `/api/v1`:

- `GET /scans/{scan_id}`
- `GET /findings?severity=&image_digest=&limit=&offset=`
- `GET /alerts?status=&limit=&offset=`
- `GET /audit?actor=&event_type=&limit=&offset=`

Collection endpoints return the same `{items, limit, offset, count, total}`
envelope, where `count` is the returned page size and `total` is the filtered
result count. The router depends on a provider interface so
the database adapter can be wired without changing the public contract.

`SqlAlchemyScanDataProvider` is the canonical read adapter for scans, findings,
and audit records. Runtime alerts may be supplied through its alert-provider
callback until runtime alerts receive a shared persistent model.
Filter values are trimmed and normalized to lowercase before reaching the data
provider, so clients can send ` HIGH ` without creating a second filter shape.

Finding records include `lifecycle_status` (`open` or `resolved`),
`resolved_at`, and `reopened_at`. A completed scan resolves previously open
fingerprints absent from that scan; a later observation clears `resolved_at` and
records the reopen time. Partial or failed scans do not close findings because
they are not complete absence evidence.
