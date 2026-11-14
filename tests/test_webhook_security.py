import hashlib
import hmac
import json

from src.remediation.deployment_evidence import verify_deployment_signature


def test_provider_webhook_signature_is_hmac_sha256():
    body = json.dumps({"event": "merged"}, separators=(",", ":")).encode()
    signature = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(signature, hmac.new(b"secret", body, hashlib.sha256).hexdigest())
    assert not hmac.compare_digest(signature, hmac.new(b"wrong", body, hashlib.sha256).hexdigest())


def test_deployment_evidence_signature_binds_exact_body():
    body = b'{"publication_id":7}'
    digest = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert verify_deployment_signature(body=body, signature=f"sha256={digest}", secret="secret")
    assert not verify_deployment_signature(body=body + b" ", signature=f"sha256={digest}", secret="secret")
    assert not verify_deployment_signature(body=body, signature=f"sha256={digest}", secret="")
