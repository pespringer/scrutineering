# Scan Queue Priorities

Scan tasks use `scan.high`, `scan.normal`, and `scan.low` queues. Critical
severity or deadline-bound work maps to high priority; routine scans use the
normal queue; low/unknown severity work uses the low queue.

Workers should consume the queues in priority order and configure
`CELERY_QUEUES` to include the queues they are responsible for. The policy is
pure and tested independently from broker delivery.
