# Scan Data API v1

`src.scan.api.router` defines the shared read contract under `/api/v1`:

- `GET /scans/{scan_id}`
- `GET /findings?severity=&image_digest=&limit=&offset=`
- `GET /alerts?status=&limit=&offset=`
- `GET /audit?actor=&event_type=&limit=&offset=`

Collection endpoints return the same `{items, limit, offset, count}` envelope
and enforce bounded pagination. The router depends on a provider interface so
the database adapter can be wired without changing the public contract.

`SqlAlchemyScanDataProvider` is the canonical read adapter for scans, findings,
and audit records. Runtime alerts may be supplied through its alert-provider
callback until runtime alerts receive a shared persistent model.
