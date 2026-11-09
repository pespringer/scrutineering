# Staging Rollback Drill

Run `npm run drill:staging-rollback` before production promotion. The drill
proves that a matching immutable digest with a completed non-regressing scan is
accepted, while digest drift and finding increases require rollback.
