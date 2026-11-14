"""Pure helpers for presenting first-run operator readiness."""

from __future__ import annotations


def onboarding_summary(steps: list[dict[str, object]]) -> dict[str, object]:
    """Summarize required, optional, and deferred setup steps."""
    required = [step for step in steps if step.get("status") not in {"optional", "deferred"}]
    completed = sum(step.get("status") == "ready" for step in required)
    blocked = [str(step["key"]) for step in required if step.get("status") == "blocked"]
    actions = [str(step["key"]) for step in required if step.get("status") == "action"]
    return {
        "status": "blocked" if blocked else ("action_required" if actions else "ready"),
        "completed": completed,
        "required": len(required),
        "blocked": blocked,
        "actions": actions,
        "steps": steps,
    }
