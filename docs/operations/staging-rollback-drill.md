# Staging Rollback Drill

Run `npm run drill:staging-rollback` before production promotion. The drill
proves that a matching immutable digest with a completed non-regressing scan is
accepted, while digest drift and finding increases require rollback.

Run `npm run drill:staging-readiness` as the companion preflight. It validates
the local production boundaries and monitoring assets; it does not replace a
rollback against the deployed staging services or a live alert-delivery test.
