from src.api.service_auth import sign_service_request, verify_service_request


def test_service_request_auth_is_body_and_time_bound():
    headers = sign_service_request("scanner", b"payload", "secret", timestamp=100)
    assert verify_service_request(headers, b"payload", "secret", now=101)
    assert not verify_service_request(headers, b"changed", "secret", now=101)
    assert not verify_service_request(headers, b"payload", "secret", now=500)
