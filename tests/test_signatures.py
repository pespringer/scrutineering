from src.scan.signatures import CosignVerifier


def test_cosign_verifier_uses_exec_style_arguments(monkeypatch):
    calls = []

    class Result:
        returncode = 0

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Result()

    monkeypatch.setattr("src.scan.signatures.subprocess.run", fake_run)
    verifier = CosignVerifier(cosign_bin="cosign-test", oidc_issuer="https://issuer.example")
    envelope = {"signature": {"identity": "ci@example", "value": "signature"}}
    assert verifier(envelope, b"artifact") is True
    assert calls[0][0][:4] == ["cosign-test", "verify-blob", "--signature", calls[0][0][3]]
    assert calls[0][1]["check"] is False


def test_cosign_verifier_rejects_nonzero_exit(monkeypatch):
    class Result:
        returncode = 1

    monkeypatch.setattr("src.scan.signatures.subprocess.run", lambda *args, **kwargs: Result())
    assert not CosignVerifier()( {"signature": {"identity": "id", "value": "sig"}}, b"artifact")


def test_cosign_verifier_enforces_keyless_identity_policy(monkeypatch):
    class Result:
        returncode = 0
    monkeypatch.setattr("src.scan.signatures.subprocess.run", lambda *args, **kwargs: Result())
    verifier = CosignVerifier(policy={"identity": "trusted@example", "issuer": "https://issuer.example", "required": True}, oidc_issuer="https://issuer.example")
    assert verifier({"signature": {"identity": "trusted@example", "value": "sig"}}, b"artifact")
    assert not verifier({"signature": {"identity": "other@example", "value": "sig"}}, b"artifact")


def test_cosign_verifier_passes_embedded_certificate(monkeypatch):
    calls = []

    class Result:
        returncode = 0

    def fake_run(command, **kwargs):
        calls.append(command)
        return Result()

    monkeypatch.setattr("src.scan.signatures.subprocess.run", fake_run)
    verifier = CosignVerifier(cosign_bin="cosign-test")
    assert verifier({"signature": {"identity": "ci@example", "value": "signature", "certificate": "pem"}}, b"artifact")
    assert "--certificate" in calls[0]
