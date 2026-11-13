import subprocess

import pytest

from src.remediation.publisher import publish_remediation_branch


def _git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)


def test_publisher_creates_new_branch_for_validated_commit(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "test")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    (tmp_path / "requirements.txt").write_text("requests==2.0\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "initial")
    commit = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "--bare", str(remote))
    _git(tmp_path, "remote", "add", "origin", str(remote))

    result = publish_remediation_branch(tmp_path, commit, "scrutineering/remediation-1")

    assert result["commit"] == commit
    assert _git(tmp_path, "show-ref", "--verify", "refs/heads/scrutineering/remediation-1")
    refs = subprocess.run(["git", "--git-dir", str(remote), "show-ref", "refs/heads/scrutineering/remediation-1"], check=True, capture_output=True, text=True)
    assert commit in refs.stdout


def test_publisher_rejects_unsafe_branch_name(tmp_path):
    with pytest.raises(ValueError, match="invalid remediation branch"):
        publish_remediation_branch(tmp_path, "abc123", "../unsafe")
