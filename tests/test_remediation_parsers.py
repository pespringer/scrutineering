import pytest

from src.remediation.parsers import update_dockerfile_base, update_exact_dependency, update_json_dependency


def test_parsers_require_one_exact_match():
    assert update_dockerfile_base("FROM python:3.11\n", "python:3.11", "python:3.12") == "FROM python:3.12\n"
    assert update_exact_dependency("requests==2.31\n", "requests", "2.31", "2.32") == "requests==2.32\n"
    assert update_json_dependency('{"requests":"2.31"}', "requests", "2.31", "2.32") == '{"requests":"2.32"}'
    with pytest.raises(ValueError, match="unique"):
        update_dockerfile_base("FROM old\nFROM old\n", "old", "new")
