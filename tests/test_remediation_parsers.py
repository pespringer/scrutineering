import pytest

from src.remediation.parsers import (
    update_cargo_dependency,
    update_dependency_file,
    update_dockerfile_base,
    update_exact_dependency,
    update_go_module_dependency,
    update_json_dependency,
    update_requirements_dependency,
)


def test_parsers_require_one_exact_match():
    assert update_dockerfile_base("FROM python:3.11\n", "python:3.11", "python:3.12") == "FROM python:3.12\n"
    assert update_exact_dependency("requests==2.31\n", "requests", "2.31", "2.32") == "requests==2.32\n"
    assert update_json_dependency('{"requests":"2.31"}', "requests", "2.31", "2.32") == '{"requests":"2.32"}'
    with pytest.raises(ValueError, match="unique"):
        update_dockerfile_base("FROM old\nFROM old\n", "old", "new")


def test_language_specific_dependency_parsers_are_exact():
    assert update_requirements_dependency("requests==2.31 # pinned\n", "requests", "2.31", "2.32") == "requests==2.32 # pinned\n"
    assert update_go_module_dependency("example.com/lib v1.2.3\n", "example.com/lib", "v1.2.3", "v1.2.4") == "example.com/lib v1.2.4\n"
    assert update_cargo_dependency('serde = "1.0.1"\n', "serde", "1.0.1", "1.0.2") == 'serde = "1.0.2"\n'
    assert update_dependency_file('requests==2.31\n', "requirements.txt", "requests", "2.31", "2.32") == 'requests==2.32\n'
    with pytest.raises(ValueError, match="unsupported"):
        update_dependency_file("x", "unknown.lock", "x", "1", "2")
