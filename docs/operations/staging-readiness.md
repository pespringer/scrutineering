# Staging Readiness Validation

Batch 7 adds a deterministic release-readiness drill that exercises the
production boundaries without requiring live cloud credentials:

```bash
npm run drill:staging-readiness
```

Run the provider-to-post-merge companion drill as well:

```bash
npm run drill:staging-provider
```

The drill verifies that the database model creates the audit, anchoring, and
remediation-event tables; service requests authenticate and reject replay;
Redis-backed scan caching and checkpointed runtime delivery work together;
audit heads can be durably anchored; keyless release evidence accepts the
configured production identity; and the checked-in Prometheus/Grafana
monitoring assets cover the required operational signals.

Run it through the complete local gate with:

```bash
npm run verify:local
```

This is a deterministic preflight, not a substitute for live staging. Before
production promotion, operators must run the deployed migrations, use the real
OIDC/Cosign identity and secret store, exercise Redis and PostgreSQL over the
staging network, confirm dashboard data and alert delivery, and record a
successful rollback drill. Do not mark the release Go until those live checks
are attached to the release record.

The provider drill covers the publication-to-merge-to-verification path. It is
deterministic locally; live staging must additionally deliver a real signed
provider callback and attach deployment scan evidence.
