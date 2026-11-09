from src.runtime.replay_checkpoint import ReplayCheckpoint


def test_replay_checkpoint_round_trip(tmp_path):
    checkpoint = ReplayCheckpoint(tmp_path / "checkpoint.json")
    assert checkpoint.load() == 0
    checkpoint.save(12)
    assert checkpoint.load() == 12
