"""Deterministic operator recovery lifecycle drill."""

from src.remediation.recovery import transition_recovery_status


def main() -> None:
    state = transition_recovery_status("requested", "acknowledged")
    assert state == "acknowledged"
    state = transition_recovery_status(state, "completed")
    assert state == "completed"
    try:
        transition_recovery_status(state, "requested")
    except ValueError:
        print("PASS recovery lifecycle and terminal-state guard")
        return
    raise AssertionError("terminal recovery state was reopened")


if __name__ == "__main__":
    main()
