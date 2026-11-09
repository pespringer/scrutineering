"""Dependency readiness checks for deployment probes."""

from __future__ import annotations

from sqlalchemy import text


def check_database(session_factory) -> dict[str, str]:
    try:
        with session_factory() as session:
            session.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as exc:
        return {"status": "not_ready", "reason": str(exc)[:200]}
