"""People who have signed in: the admin's access review, and who findings can be assigned to."""

from __future__ import annotations

from fastapi import APIRouter, Request

from src.api.roles import require_action
from src.api.serializers import iso
from src.db.connection import get_session
from src.db.models import Principal

router = APIRouter()


@router.get("/people")
def list_people(request: Request) -> dict:
    """Everyone recorded at sign-in, most recently seen first, with the roles they last had."""
    require_action(request, "people.view")
    with get_session() as session:
        people = session.query(Principal).order_by(Principal.last_seen_at.desc(), Principal.id.desc()).all()
        items = [
            {
                "subject": person.subject,
                "email": person.email,
                "roles": person.roles or [],
                "first_seen_at": iso(person.first_seen_at),
                "last_seen_at": iso(person.last_seen_at),
            }
            for person in people
        ]
    return {"items": items, "count": len(items)}


@router.get("/people/assignees")
def list_assignees(request: Request) -> dict:
    """Who findings can be assigned to: subject and email only, for anyone who triages findings."""
    require_action(request, "findings.triage")
    with get_session() as session:
        people = session.query(Principal.subject, Principal.email).order_by(Principal.email, Principal.subject).all()
    return {"items": [{"subject": subject, "email": email} for subject, email in people]}
