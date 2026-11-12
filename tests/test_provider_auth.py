from src.remediation.provider_auth import credential_diagnostics


def test_credential_diagnostics_redacts_token_and_accepts_rotation_metadata(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret-value")
    monkeypatch.setenv("GITHUB_TOKEN_ROTATED_AT", "2026-11-01T00:00:00Z")
    result = credential_diagnostics("github")
    assert result["configured"] is True
    assert result["token_present"] is True
    assert "secret-value" not in str(result)
    assert result["rotation_metadata_valid"] is True
