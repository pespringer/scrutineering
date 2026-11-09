import asyncio

import pytest

from src.scan.circuit_breaker import CircuitBreaker, CircuitOpenError
from src.scan.scanners.base import ScannerError
from src.scan.scan_service import ScanService


def test_circuit_opens_after_threshold_and_resets():
    now = [0.0]
    breaker = CircuitBreaker(failure_threshold=2, reset_timeout=10, clock=lambda: now[0])
    breaker.record_failure()
    assert breaker.allow()
    breaker.record_failure()
    assert not breaker.allow()
    now[0] = 10.0
    assert breaker.allow()


def test_scan_service_short_circuits_repeated_scanner_outages():
    class BrokenScanner:
        async def scan(self, image_name):
            raise ScannerError("trivy", "down")

    service = ScanService(scanner_retry_attempts=0, scanner_circuit_failure_threshold=1, scanner_circuit_reset_timeout=60)
    scanner = BrokenScanner()
    with pytest.raises(ScannerError):
        asyncio.run(service._run_single(scanner, "alpine:3.20", "trivy"))
    with pytest.raises(CircuitOpenError):
        asyncio.run(service._run_single(scanner, "alpine:3.20", "trivy"))
