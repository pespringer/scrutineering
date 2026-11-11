import pytest

from src.remediation.adapter import build_exact_match_changes, build_validation_sequence


def test_adapter_normalizes_exact_match_actions():
    assert build_exact_match_changes([{"file_path": "Dockerfile", "before_value": "FROM a", "after_value": "FROM b"}]) == [{"file_path": "Dockerfile", "expected": "FROM a", "replacement": "FROM b"}]


@pytest.mark.parametrize("file_path", ["/tmp/Dockerfile", "../Dockerfile", ""])
def test_adapter_rejects_unsafe_paths(file_path):
    with pytest.raises(ValueError):
        build_exact_match_changes([{"file_path": file_path, "before_value": "a", "after_value": "b"}])


def test_validation_sequence_contains_all_required_gates():
    commands = build_validation_sequence("github", "python")
    assert [command[0] for command in commands] == ["python", "pytest", "python", "syft", "trivy"]


def test_validation_sequence_rejects_unknown_provider():
    with pytest.raises(ValueError):
        build_validation_sequence("unknown", "python")
