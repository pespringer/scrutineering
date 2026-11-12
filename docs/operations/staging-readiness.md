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
remediation-event and release-evidence tables; service requests authenticate and reject replay;
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

Recovery polling runs on the `remediation.normal` queue. It reads provider
credentials only from the API/worker environment, records every attempt in the
remediation timeline, retries with bounded backoff, and emits an escalation
event when a publication remains stale for the configured cycle count.

The readiness gate also checks alert-evidence schema coverage, worker task
registration, provider-failure telemetry, and the dashboard recovery panel.

The full local recovery drill should also verify that retention cleanup remains
a dry run by default, dead-letter records can be replayed, provider calls are
leased across workers, and status changes include an operator reason code.

Run the receiver-independent lifecycle drill with:

```bash
npm run drill:staging-recovery
```

This uses only the deterministic fake receiver and never contacts an external
alert service.

`npm run validate:release-readiness` runs the same gate in CI. It does not
enable alert delivery or purge retention data.

Evidence exports can be signed and verified locally with `npm run evidence:sign`
and `npm run evidence:verify`; secrets are supplied on the command line or by
the calling secret manager and are never written to repository files.
