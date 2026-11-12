import pytest

from src.remediation.backup import verify_restore_preflight
from src.remediation.provider_resilience import ProviderResponse, bounded_provider_page, response_from_headers
from src.platform.controls import backup_manifest


def test_provider_response_and_retry_headers_are_bounded():
    response = response_from_headers(429, {"error": "rate_limited"}, {"retry-after": "30"})
    assert response.retry_after == 30
    with pytest.raises(ValueError): ProviderResponse(200, {}, schema_version="v2").validate()
    with pytest.raises(ValueError): bounded_provider_page([{}] * 101, None)


def test_restore_preflight_requires_matching_backup_manifest():
    records = [{"id": 1}]
    assert verify_restore_preflight(records, backup_manifest(records, source="postgres"))
    assert not verify_restore_preflight(records, backup_manifest([], source="postgres"))
