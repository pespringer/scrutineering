# Scan Schedules

Each active image can have a durable operator-managed scan cadence. A schedule
is bounded to five minutes through thirty days and is evaluated by the existing
Celery Beat inventory task. The scheduler queues only images whose
`next_run_at` is due; paused schedules are retained for auditability and are
not deleted.

## Dashboard

Open an image from the inventory and use **Automated scanning** to choose an
hourly, six-hour, twelve-hour, daily, or weekly cadence. **Pause** stops future
automatic scans without archiving the image. The image detail page shows the
next planned run when one is scheduled.

## API

Read the current schedule with:

```bash
curl http://localhost:3001/api/images/123/schedule
```

Operators can create or update one with:

```bash
curl -X POST http://localhost:3001/api/images/123/schedule \
  -H 'content-type: application/json' \
  -d '{"enabled":true,"interval_seconds":21600}'
```

Schedule changes are role-protected and recorded in the audit log. The
endpoint does not start a scan immediately; the next due inventory pass queues
it through the normal low-priority scan queue.
