import pytest
from src.scan.cosign_policy import load_cosign_policy


def test_production_cosign_policy_requires_keyless_identity():
    with pytest.raises(ValueError): load_cosign_policy({"NODE_ENV": "production"})
    result = load_cosign_policy({"NODE_ENV": "production", "COSIGN_CERTIFICATE_IDENTITY": "ci@example", "COSIGN_OIDC_ISSUER": "https://issuer.test"})
    assert result["required"] is True
