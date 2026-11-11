import json

from src.remediation.provider_publishers import publish_validated_plan


class Response:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode()


def test_github_publisher_checks_protection_then_publishes():
    urls = []

    def transport(request, timeout=20):
        urls.append(request.full_url)
        if request.full_url.endswith("/protection"):
            return Response({})
        return Response({"number": 9, "html_url": "https://github.test/pr/9"})

    result = publish_validated_plan(
        provider="github", repository="acme/api", title="Fix", body="Details",
        head="auto/fix", base="main", token="secret", idempotency_key="run-1",
        transport=transport,
    )
    assert result.number == 9
    assert urls[0].endswith("/branches/main/protection")
    assert urls[1].endswith("/pulls")
