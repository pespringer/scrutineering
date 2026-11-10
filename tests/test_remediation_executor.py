import subprocess

from src.remediation.executor import execute_remediation
from src.scan.evidence import build_evidence


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


def test_executor_can_commit_validated_changes_in_isolation(tmp_path):
    repo = make_repo(tmp_path)
    result = execute_remediation(
        repo, ["committed\n"], lambda worktree, change: (worktree / "config.txt").write_text(change),
        [], evidence_verified=True, base_dir=tmp_path, commit_message="Apply validated fix",
    )
    assert result.status == "ready"
    assert result.commit
    assert "config.txt" in result.changed_files


def test_executor_verifies_evidence_envelope_at_boundary(tmp_path):
    repo = make_repo(tmp_path)
    artifact = {"packages": []}
    envelope = build_evidence(
        artifact=artifact, artifact_type="sbom", format="spdx-json",
        subject_digest="sha256:" + "a" * 64, tool_name="syft", tool_version="1",
        signature_provider="cosign", signature_identity="id", signature_value="x" * 16,
        generated_at="2026-11-08T12:00:00Z",
    )
    result = execute_remediation(
        repo, [], lambda *_: None, [], evidence_envelope=envelope,
        evidence_artifact=artifact, evidence_verifier=lambda *_: True,
    )
    assert result.status == "ready"


def test_executor_can_select_production_release_evidence_boundary(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    calls = []
    monkeypatch.setattr("src.remediation.executor.verify_release_evidence", lambda envelope, artifact, **kwargs: calls.append(kwargs) or True)
    result = execute_remediation(
        repo, [], lambda *_: None, [], evidence_envelope={"version": "1.0.0"},
        evidence_artifact=b"artifact", release_evidence=True,
        evidence_env={"NODE_ENV": "production"},
    )
    assert result.status == "ready"
    assert calls[0]["env"] == {"NODE_ENV": "production"}
