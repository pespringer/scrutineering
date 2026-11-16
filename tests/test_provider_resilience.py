import pytest

from src.remediation.provider_resilience import ProviderResponse, bounded_provider_page, response_from_headers


def test_provider_response_and_retry_headers_are_bounded():
    response = response_from_headers(429, {"error": "rate_limited"}, {"retry-after": "30"})
    assert response.retry_after == 30
    with pytest.raises(ValueError): ProviderResponse(200, {}, schema_version="v2").validate()
    with pytest.raises(ValueError): bounded_provider_page([{}] * 101, None)
