from src.scan.registry import registry_env_keys


def test_registry_credential_requirements_are_explicit():
    assert registry_env_keys("ecr") == ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    assert registry_env_keys("private.example") == ()
