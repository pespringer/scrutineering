import subprocess

from src.remediation.worktree import RemediationWorktree


def test_worktree_isolated_and_cleaned(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "tracked.txt").write_text("base\n")
    subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "base"],
        check=True,
    )

    with RemediationWorktree(repo, tmp_path) as worktree:
        assert worktree != repo
        assert (worktree / "tracked.txt").read_text() == "base\n"
        (worktree / "tracked.txt").write_text("remediated\n")
        assert (repo / "tracked.txt").read_text() == "base\n"
        created_path = worktree

    assert not created_path.exists()
