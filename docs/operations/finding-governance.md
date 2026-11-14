# Finding Governance

Finding suppressions are durable, expiring exceptions. They do not delete a
finding or change scanner results; they record why an operator accepted the
risk and when that exception must be reconsidered.

## Dashboard workflow

On an image detail page, select one or more findings and choose **Suppress 30
days**. Enter a short reason that will make sense during a later review. The
dashboard displays a `Suppressed` badge and keeps the exception visible in the
finding payload. Expiration is automatic; an expired exception is no longer
active and the finding remains open.

Operators can revoke an active exception through the API:

```bash
curl -X POST http://localhost:3001/api/findings/unsuppress \
  -H 'content-type: application/json' \
  -d '{"ids":[123]}'
```

## API contract

`POST /api/dashboard/findings/suppress` accepts `finding_ids`, a required
`reason`, and an optional future `expires_at`. Each change is recorded in the
operator audit log. Creating a new exception revokes any existing active
exception for the same finding. `POST /api/dashboard/findings/unsuppress`
revokes active exceptions without deleting their history.

Only `operator` and `security-operator` roles may change suppression state.
Read-only dashboard users can see the suppression status but cannot mutate it.

Apply migrations before using the endpoints:

```bash
docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade head
```
