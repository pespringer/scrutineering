import pytest
from src.scan.cosign_policy import load_cosign_policy, identity_allowed


def test_production_cosign_policy_requires_keyless_identity():
    with pytest.raises(ValueError): load_cosign_policy({"NODE_ENV": "production"})
    result = load_cosign_policy({"NODE_ENV": "production", "COSIGN_CERTIFICATE_IDENTITY": "ci@example", "COSIGN_OIDC_ISSUER": "https://issuer.test"})
    assert result["required"] is True
    assert identity_allowed("ci@example", result)


def test_non_production_policy_can_still_require_explicit_identity():
    result = load_cosign_policy({"COSIGN_CERTIFICATE_IDENTITY": "*.example"})
    assert result["required"] is True
    assert identity_allowed("pipeline.example", result)
    assert not identity_allowed("attacker.invalid", result)
