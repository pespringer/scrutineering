# Scan Queue Priorities

Scan tasks use `scan.high`, `scan.normal`, and `scan.low` queues. Critical
severity or deadline-bound work maps to high priority; routine scans use the
normal queue; low/unknown severity work uses the low queue.

Workers should consume the queues in priority order and configure
`CELERY_QUEUES` to include the queues they are responsible for. The policy is
pure and tested independently from broker delivery.

Call `src.scan.tasks.enqueue_scan(image_name, priority="high")` from API or
scheduler code so queue selection is centralized rather than duplicated at
call sites.

Scanner outcomes are exported as `scrutineering_scans_total` with `status` and
`scanner` labels, including `completed`, `failed`, and `cache_hit`.
