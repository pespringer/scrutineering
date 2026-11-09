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


def check_dependencies(session_factory, checks: dict[str, callable] | None = None) -> dict[str, object]:
    results = {"database": check_database(session_factory)}
    for name, check in (checks or {}).items():
        try: results[name] = check()
        except Exception as exc: results[name] = {"status": "not_ready", "reason": str(exc)[:200]}
    return {"status": "ready" if all(value.get("status") == "ready" for value in results.values()) else "not_ready", "dependencies": results}
