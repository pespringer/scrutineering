# Audit Integrity

Forensic `AuditLogger` records now carry `previous_hash` and `record_hash`
fields. Each hash covers the canonical record payload, creating a tamper-
evident in-process chain while preserving append-only behavior.

Audit chains can now be sent through the `AuditAnchor` adapter for external
anchoring. The chain is not yet anchored outside the process or persisted in dedicated
database columns. Production should anchor periodic heads and reject gaps or
unexpected previous hashes during audit export.

`verify_audit_chain()` performs that local export check and returns false on
any link or payload-hash mismatch.

Migration `20261109_02` adds nullable hash columns to `audit_log` so existing
records remain readable while new records can be anchored and indexed.
