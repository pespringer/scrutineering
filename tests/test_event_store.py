from src.runtime.ebpf_agent import RuntimeEvent
from src.runtime.event_store import JsonlEventStore


def test_jsonl_event_store_persists_and_replays_recent_events(tmp_path):
    store = JsonlEventStore(tmp_path / "events.jsonl")
    store.append(RuntimeEvent(event_type="process", container_id="c1", detail={"command": "sh"}))
    store.append(RuntimeEvent(event_type="network", container_id="c1"))
    events = store.read(limit=1)
    assert len(events) == 1
    assert events[0]["event_type"] == "network"


def test_jsonl_event_store_handles_empty_state(tmp_path):
    assert JsonlEventStore(tmp_path / "missing.jsonl").read() == []
