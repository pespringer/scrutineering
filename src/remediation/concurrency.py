"""Pure lease/concurrency decisions shared by workers and tests."""

from datetime import datetime
from dataclasses import dataclass


def lease_available(lease_until: datetime | None, now: datetime) -> bool:
    return lease_until is None or lease_until <= now


def next_version(current: int | None) -> int:
    return (current or 0) + 1


@dataclass(frozen=True)
class LeaseState:
    owner: str | None
    until: datetime | None
    version: int


def heartbeat(state: LeaseState, *, owner: str, until: datetime) -> LeaseState:
    if state.owner != owner:
        raise ValueError("lease owner mismatch")
    return LeaseState(owner=owner, until=until, version=next_version(state.version))


def reclaim(state: LeaseState, *, now: datetime) -> LeaseState:
    if not lease_available(state.until, now):
        raise ValueError("lease is still active")
    return LeaseState(owner=None, until=None, version=next_version(state.version))


def check_version(expected: int, actual: int) -> None:
    if expected != actual:
        raise ValueError("concurrent update detected")
