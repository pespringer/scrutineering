# Provider Integration

Scrutineering has a single authentication boundary for planner requests. API
keys remain available for local and service bootstrap, while
`startConfiguredPlannerServer()` adds HTTPS OIDC discovery, rotating JWKS
verification, issuer/audience checks, bounded clock skew, and verified claim
mapping to the internal principal shape.

The Python API accepts body-bound internal service requests signed with
`SERVICE_AUTH_SECRET`. Signatures include the service name, timestamp, and
request body. The replay guard rejects a signature more than once and rejects
timestamps outside `SERVICE_AUTH_MAX_SKEW_SECONDS`.

Registry credentials are loaded through `src.scan.registry` so Docker Hub,
GHCR, GitLab, ECR, and GCR use explicit, testable environment mappings.
Incomplete credential pairs fail closed. Secrets are only returned to the
scanner login adapter and are never included in logs or image identity data.

Audit chain heads can be published through `AuditLogger.anchor_head()`. The
method verifies the in-memory chain, publishes a `sha256:`-qualified head to
an external `AuditAnchor`, and accepts a persistence callback for the returned
receipt. Migration `20261109_05` provides the durable
`audit_chain_anchors` table; use `AuditLogRepository.record_anchor()` for
database-backed receipts.
