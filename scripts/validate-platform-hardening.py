"""Validate receiver-independent platform hardening contracts."""

from src.platform.controls import QueueHealth, RetentionPolicy, RetryPolicy, guard_changed_files


assert not RetentionPolicy().can_purge()
assert RetryPolicy().delay(1) > 0
assert guard_changed_files(["src/platform/controls.py"])
assert QueueHealth(0, 0).status() == "healthy"
print("PASS platform hardening contracts")
