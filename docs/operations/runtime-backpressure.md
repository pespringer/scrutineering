# Runtime Backpressure

The runtime agent keeps a bounded 10,000-event buffer. If consumers fall
behind, the oldest buffered event is discarded and the backend continues
streaming; this prevents a dashboard outage from stalling security monitoring.

`EBPFMonitorAgent.buffer_stats()` exposes buffered count, capacity, and dropped
events for degraded-health reporting. Dropped-event counts should be alerted on
in production until durable event delivery is implemented.
