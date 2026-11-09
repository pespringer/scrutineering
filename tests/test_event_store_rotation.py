from src.runtime.ebpf_agent import RuntimeEvent
from src.runtime.event_store import JsonlEventStore


def test_event_store_rotates_bounded_files(tmp_path):
    store = JsonlEventStore(tmp_path / "events.jsonl", max_bytes=1)
    store.append(RuntimeEvent(event_type="first", container_id="c"))
    store.append(RuntimeEvent(event_type="second", container_id="c"))
    assert (tmp_path / "events.jsonl.1").exists()
