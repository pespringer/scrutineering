# Runtime Backpressure

The runtime agent keeps a bounded 10,000-event buffer. If consumers fall
behind, the oldest buffered event is discarded and the backend continues
streaming; this prevents a dashboard outage from stalling security monitoring.

`EBPFMonitorAgent.buffer_stats()` exposes buffered count, capacity, and dropped
events for degraded-health reporting. Dropped-event counts should be alerted on
in production until durable event delivery is implemented.

`JsonlEventStore` provides the first durable sink. The agent writes and fsyncs
events before buffering them, and exposes sink failures alongside dropped-event
counts. Production deployments should replace JSONL with a managed durable
queue or database once retention and replay policies are defined.

The JSONL sink rotates the active file once `max_bytes` is reached, keeping a
single previous segment for bounded local storage.

`EBPFMonitorAgent.capability_report()` exposes whether BCC and the kernel
tracing interface are present, making fallback mode visible instead of silently
appearing healthy.
The durable JSONL sink supports bounded replay by event count and optional
`container_id` filtering, which lets operators drain one workload without
loading the entire event history.
