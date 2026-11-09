from __future__ import annotations

from dataclasses import dataclass
from .post_merge import evaluate_post_merge


@dataclass
class PostMergeCoordinator:
    rollback: callable

    def verify(self, **kwargs) -> dict[str, object]:
        result = evaluate_post_merge(**kwargs)
        if result["status"] == "rollback_required":
            self.rollback(result)
        return result
