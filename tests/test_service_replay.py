from src.api.service_auth import create_replay_guard


def test_service_replay_guard_rejects_duplicate_signatures():
    guard = create_replay_guard()
    assert guard("sig", 100) is True
    assert guard("sig", 101) is False
