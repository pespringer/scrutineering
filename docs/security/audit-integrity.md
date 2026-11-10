# Audit Integrity

Forensic `AuditLogger` records now carry `previous_hash` and `record_hash`
fields. Each hash covers the canonical record payload, creating a tamper-
evident in-process chain while preserving append-only behavior.

Audit chains can now be sent through the `AuditAnchor` adapter for external
anchoring. `AuditLogger.anchor_head()` verifies the exported chain, publishes
the `sha256:`-qualified head, and returns a receipt. Production deployments
must connect it to an append-only external anchor and persist the returned
anchor identifier. Production should anchor periodic heads and reject gaps or
unexpected previous hashes during audit export.

`verify_audit_chain()` performs that local export check and returns false on
any link or payload-hash mismatch.

Use `AuditLogger.export()` before anchoring; it verifies the chain and refuses
to return tampered records.

Migration `20261109_02` adds nullable hash columns to `audit_log` so existing
records remain readable while new records can be anchored and indexed.
Migration `20261109_05` adds `audit_chain_anchors` for durable external-anchor
receipts.
