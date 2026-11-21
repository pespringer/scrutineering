"""What each role may do: one table of actions, checked by every dashboard route (docs/design/multi-user-roles.md).

`admin` passes every action. Print the table for the operator guide with `python -m src.api.roles`.
"""

from __future__ import annotations

from fastapi import HTTPException, Request

ROLES = ("dashboard", "operator", "remediator", "security-operator", "admin")

ACTIONS: dict[str, tuple[str, frozenset[str]]] = {
    "registry.view": ("Browse the registry catalog", frozenset({"dashboard", "operator", "security-operator"})),
    "findings.export": ("Export open findings", frozenset({"dashboard", "operator", "security-operator"})),
    "scans.manage": ("Start, cancel, retry and archive scans", frozenset({"operator", "security-operator"})),
    "images.archive": ("Archive images", frozenset({"operator", "security-operator"})),
    "findings.triage": ("Acknowledge and assign findings", frozenset({"operator", "security-operator"})),
    "remediations.view": (
        "See remediations, their events and evidence",
        frozenset({"remediator", "security-operator"}),
    ),
    "remediations.propose": ("Preview and propose a fix", frozenset({"remediator", "security-operator"})),
    "remediations.execute": ("Build and rescan an approved fix", frozenset({"remediator", "security-operator"})),
    "remediations.cancel": ("Cancel a remediation", frozenset({"remediator", "security-operator"})),
    "sources.manage": ("Connect and disconnect an image's source", frozenset({"remediator", "security-operator"})),
    "remediations.approve": ("Approve a proposed fix", frozenset({"security-operator"})),
    "remediations.accept": ("Accept a fix's new critical or high findings", frozenset({"security-operator"})),
    "remediations.publish": ("Open the fix's pull request", frozenset({"security-operator"})),
    "remediations.retry": ("Restart a failed remediation", frozenset({"security-operator"})),
    "audit.export": ("Export the audit trail", frozenset({"security-operator"})),
    "compliance.export": ("Build and download compliance exports", frozenset({"security-operator"})),
    "notifications.manage": ("See notification channels and send a test", frozenset({"security-operator"})),
    "reports.build": ("Build a report on demand", frozenset()),
}


def allowed(roles, action: str) -> bool:
    if action not in ACTIONS:
        raise ValueError(f"unknown action {action!r}")
    held = set(roles)
    return "admin" in held or bool(held & ACTIONS[action][1])


def actions_for(roles) -> list[str]:
    return [action for action in ACTIONS if allowed(roles, action)]


def require_action(request: Request, action: str) -> None:
    if not allowed(getattr(request.state, "principal_roles", []), action):
        raise HTTPException(status_code=403, detail="operator_role_required")


def markdown_table() -> str:
    lines = [
        "| Action | " + " | ".join(f"`{role}`" for role in ROLES) + " |",
        "|---|" + "---|" * len(ROLES),
    ]
    for action, (label, _) in ACTIONS.items():
        marks = " | ".join("✓" if allowed([role], action) else "" for role in ROLES)
        lines.append(f"| {label} (`{action}`) | {marks} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(markdown_table(), end="")
