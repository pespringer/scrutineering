from src.runtime.ebpf_agent import RuntimeEvent
from src.runtime.event_store import JsonlEventStore


def test_jsonl_event_store_persists_and_replays_recent_events(tmp_path):
    store = JsonlEventStore(tmp_path / "events.jsonl")
    store.append(RuntimeEvent(event_type="process", container_id="c1", detail={"command": "sh"}))
    store.append(RuntimeEvent(event_type="network", container_id="c1"))
    events = store.read(limit=1)
    assert len(events) == 1
    assert events[0]["event_type"] == "network"
    assert store.read(container_id="c1", limit=2)[0]["event_type"] == "process"


def test_jsonl_event_store_handles_empty_state(tmp_path):
    assert JsonlEventStore(tmp_path / "missing.jsonl").read() == []


def test_jsonl_event_store_skips_corrupt_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("not-json\n")
    assert JsonlEventStore(path).read() == []


def test_jsonl_event_store_reads_from_checkpoint_offset(tmp_path):
    store = JsonlEventStore(tmp_path / "events.jsonl")
    store.append(RuntimeEvent(event_type="process", container_id="c1"))
    store.append(RuntimeEvent(event_type="network", container_id="c1"))
    offset, events = store.read_from(1, 10)
    assert offset == 2
    assert [event["event_type"] for event in events] == ["network"]
