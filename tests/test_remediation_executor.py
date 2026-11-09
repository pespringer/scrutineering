import subprocess

from src.remediation.executor import execute_remediation


def make_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "config.txt").write_text("old\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "base"], check=True)
    return repo


def test_executor_requires_verified_evidence(tmp_path):
    result = execute_remediation(tmp_path, [], lambda *_: None, [], evidence_verified=False)
    assert result.status == "blocked"


def test_executor_applies_changes_and_validates_in_isolation(tmp_path):
    repo = make_repo(tmp_path)

    def apply_change(worktree, change):
        (worktree / "config.txt").write_text(change)

    result = execute_remediation(
        repo, ["new\n"], apply_change, [["git", "diff", "--exit-code", "--", "config.txt"]],
        evidence_verified=True, base_dir=tmp_path,
    )
    # The command intentionally expects no diff and therefore fails closed.
    assert result.status == "failed"
    assert result.commands[0]["returncode"] != 0
    assert (repo / "config.txt").read_text() == "old\n"

    result = execute_remediation(
        repo, ["new\n"], apply_change, [["git", "diff", "--quiet", "--exit-code", "--", "missing.txt"]],
        evidence_verified=True, base_dir=tmp_path,
    )
    assert result.status == "ready"
    assert "config.txt" in result.changed_files
