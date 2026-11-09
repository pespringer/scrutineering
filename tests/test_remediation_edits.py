import pytest

from src.remediation.edits import replace_text


def test_replace_text_requires_one_unambiguous_match(tmp_path):
    target = tmp_path / "Dockerfile"
    target.write_text("FROM python:3.12\n")
    replace_text(tmp_path, "Dockerfile", "FROM python:3.12", "FROM python:3.13")
    assert target.read_text() == "FROM python:3.13\n"


def test_replace_text_rejects_ambiguous_and_escape_paths(tmp_path):
    (tmp_path / "config").write_text("x x")
    with pytest.raises(ValueError, match="matches"):
        replace_text(tmp_path, "config", "x", "y")
    with pytest.raises(ValueError, match="escapes"):
        replace_text(tmp_path, "../outside", "x", "y")
