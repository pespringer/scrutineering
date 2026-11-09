"""Small in-process circuit breaker for failing external scanner binaries."""

import time


class CircuitOpenError(RuntimeError):
    """Raised when a scanner has exceeded its failure threshold."""


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, reset_timeout: float = 60.0, clock=time.monotonic):
        if failure_threshold < 1 or reset_timeout < 0:
            raise ValueError("circuit breaker settings are invalid")
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._clock = clock
        self._failures = 0
        self._opened_at = None

    def allow(self) -> bool:
        if self._opened_at is None:
            return True
        if self._clock() - self._opened_at >= self.reset_timeout:
            self._opened_at = None
            self._failures = 0
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = self._clock()

    @property
    def is_open(self) -> bool:
        return self._opened_at is not None and not self.allow()
