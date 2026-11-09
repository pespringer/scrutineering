from src.scan.registry import resolve_registry_digest


class Headers:
    def get(self, name):
        return "sha256:" + "d" * 64 if name == "Docker-Content-Digest" else None


class Response:
    headers = Headers()


def test_registry_resolver_uses_manifest_head_and_bearer_token():
    requests = []
    def opener(request):
        requests.append(request)
        return Response()

    digest = resolve_registry_digest("registry.example", "acme/api", "v1", token="token", opener=opener)
    assert digest == "sha256:" + "d" * 64
    assert requests[0].method == "HEAD"
    assert requests[0].headers["Authorization"] == "Bearer token"


def test_registry_resolver_rejects_missing_digest():
    class EmptyResponse:
        class EmptyHeaders:
            def get(self, name): return None
        headers = EmptyHeaders()
    try:
        resolve_registry_digest("registry.example", "acme/api", "latest", opener=lambda _: EmptyResponse())
    except RuntimeError as error:
        assert "sha256 digest" in str(error)
    else:
        raise AssertionError("expected missing digest failure")
