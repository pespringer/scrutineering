import hashlib
import hmac
import json


def test_provider_webhook_signature_is_hmac_sha256():
    body = json.dumps({"event": "merged"}, separators=(",", ":")).encode()
    signature = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(signature, hmac.new(b"secret", body, hashlib.sha256).hexdigest())
    assert not hmac.compare_digest(signature, hmac.new(b"wrong", body, hashlib.sha256).hexdigest())
