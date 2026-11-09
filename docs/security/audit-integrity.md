# Audit Integrity

Forensic `AuditLogger` records now carry `previous_hash` and `record_hash`
fields. Each hash covers the canonical record payload, creating a tamper-
evident in-process chain while preserving append-only behavior.

The chain is not yet anchored outside the process or persisted in dedicated
database columns. Production should anchor periodic heads and reject gaps or
unexpected previous hashes during audit export.
