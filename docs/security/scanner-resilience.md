# Scanner Resilience

`ScanService` retries scanner failures with configurable bounded exponential
backoff (`SCANNER_RETRY_ATTEMPTS` and `SCANNER_RETRY_BACKOFF_SECONDS`). Each
scanner also has an in-process circuit breaker. After repeated final failures,
new work fails fast until `SCANNER_CIRCUIT_RESET_SECONDS` elapses, preventing a
broken binary or unreachable registry from consuming all worker capacity.

The breaker is intentionally local to a worker process. Shared breaker state,
distributed scan queues, and persistent scanner-result caching remain future
operational work.

`ScanCache` now provides the local caching primitive and `ScanService` can use
it for successful scanner results. It keys entries by
scanner and digest-qualified image, uses bounded TTLs, and writes atomically
with `fsync`/rename so interrupted workers do not publish partial JSON.
