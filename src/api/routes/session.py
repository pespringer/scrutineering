"""The caller's identity and role-derived capabilities."""

from __future__ import annotations


from fastapi import APIRouter, Request

from src.api.roles import actions_for


router = APIRouter()


@router.get("/session")
def dashboard_session(request: Request) -> dict:
    return {
        "authenticated": True,
        "auth_method": getattr(request.state, "auth_method", "api_key"),
        "subject": getattr(request.state, "principal_id", "dashboard-service"),
        "email": getattr(request.state, "principal_email", None),
        "roles": getattr(request.state, "principal_roles", []),
    }


@router.get("/permissions")
def dashboard_permissions(request: Request) -> dict:
    roles = set(getattr(request.state, "principal_roles", []))
    actions = actions_for(roles)
    return {
        "roles": sorted(roles),
        "actions": actions,
        "can_view": True,
        "can_manage_scans": "scans.manage" in actions,
        "can_cancel_scans": "scans.manage" in actions,
        "can_remediate": "remediations.view" in actions,
    }
