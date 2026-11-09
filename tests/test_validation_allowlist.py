from src.remediation.validation import run_validation_pipeline


def test_validation_blocks_unallowlisted_commands(tmp_path):
    commands = {phase: ["sh", "-c", "true"] for phase in ("install", "test", "build", "sbom", "rescan")}
    result = run_validation_pipeline(tmp_path, commands)
    assert result.status == "blocked"
    assert "allowlisted" in result.error
