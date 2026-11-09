from src.api.auth import is_api_key_authorized


class Request:
    def __init__(self, headers): self.headers = headers


def test_api_auth_accepts_bearer_and_x_api_key():
    assert is_api_key_authorized(Request({"authorization": "Bearer key"}), "key")
    assert is_api_key_authorized(Request({"x-api-key": "key"}), "key")
    assert not is_api_key_authorized(Request({"authorization": "Bearer wrong"}), "key")
    assert not is_api_key_authorized(Request({"authorization": "Bearer "}), "key")
