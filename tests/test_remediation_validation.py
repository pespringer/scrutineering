import sys

from src.remediation.validation import run_validation_pipeline


def test_validation_pipeline_requires_every_phase(tmp_path):
    result = run_validation_pipeline(tmp_path, {"test": ["true"]})
    assert result.status == "blocked"
    assert "install" in result.error


def test_validation_pipeline_runs_gates_in_order(tmp_path):
    commands = {phase: [sys.executable, "-c", "pass"] for phase in ("install", "test", "build", "sbom", "rescan")}
    result = run_validation_pipeline(tmp_path, commands)
    assert result.status == "passed"
    assert [phase["phase"] for phase in result.phases] == ["install", "test", "build", "sbom", "rescan"]


def test_validation_pipeline_stops_on_first_failure(tmp_path):
    commands = {phase: ["true"] for phase in ("install", "test", "build", "sbom", "rescan")}
    commands["build"] = ["false"]
    result = run_validation_pipeline(tmp_path, commands)
    assert result.status == "failed"
    assert [phase["phase"] for phase in result.phases] == ["install", "test", "build"]
