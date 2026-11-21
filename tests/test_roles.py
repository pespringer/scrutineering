"""One role matrix decides what each role may do (docs/design/multi-user-roles.md)."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import src.api.routes as routes_package
from src.api.roles import ACTIONS, ROLES, actions_for, allowed, markdown_table, require_action
from src.api.routes.session import dashboard_permissions

ROOT = Path(__file__).resolve().parents[1]

# Who could do what before the matrix existed; moving the checks into one table must not change it.
EXPECTED = {
    "dashboard": {"registry.view", "findings.export"},
    "operator": {"registry.view", "findings.export", "scans.manage", "images.archive", "findings.triage"},
    "remediator": {
        "remediations.view",
        "remediations.propose",
        "remediations.execute",
        "remediations.cancel",
        "sources.manage",
    },
    "security-operator": set(ACTIONS) - {"reports.build", "people.view"},
    "admin": set(ACTIONS),
}

# Routes that change state without a dashboard role: GitHub calls this one, signed with its own HMAC.
UNCHECKED_MUTATIONS = {("POST", "/webhooks/{provider}")}


def _routes():
    for module_info in pkgutil.iter_modules(routes_package.__path__):
        module = importlib.import_module(f"{routes_package.__name__}.{module_info.name}")
        for route in getattr(getattr(module, "router", None), "routes", []):
            yield route


def test_matrix_keeps_each_roles_behaviour():
    for role in ROLES:
        assert set(actions_for([role])) == EXPECTED[role], role


def test_no_roles_means_no_actions():
    assert actions_for([]) == []
    assert actions_for(["unknown-group"]) == []


def test_unknown_action_is_a_programming_error():
    with pytest.raises(ValueError):
        allowed(["admin"], "remediations.aprove")


def test_require_action_refuses_with_403():
    request = SimpleNamespace(state=SimpleNamespace(principal_roles=["remediator"]))
    require_action(request, "remediations.propose")
    with pytest.raises(HTTPException) as error:
        require_action(request, "remediations.approve")
    assert error.value.status_code == 403


def test_every_route_that_changes_state_checks_a_known_action():
    for route in _routes():
        mutating = set(route.methods) - {"GET", "HEAD"}
        source = inspect.getsource(route.endpoint)
        for method in mutating:
            if (method, route.path) in UNCHECKED_MUTATIONS:
                continue
            assert "require_action(request" in source, f"{method} {route.path} checks no action"
        for action in source.split('require_action(request, "')[1:]:
            assert action.split('"', 1)[0] in ACTIONS, route.path


def test_permissions_lists_the_callers_actions():
    request = SimpleNamespace(state=SimpleNamespace(principal_roles=["operator"]))
    body = dashboard_permissions(request)
    assert set(body["actions"]) == EXPECTED["operator"]
    assert body["can_manage_scans"] is True
    assert body["can_remediate"] is False


def test_operator_guide_table_matches_the_matrix():
    guide = (ROOT / "docs" / "OPERATOR_GUIDE.md").read_text()
    table = guide.split("<!-- roles:start -->\n", 1)[1].split("<!-- roles:end -->", 1)[0]
    assert table == markdown_table(), "the role table in docs/OPERATOR_GUIDE.md is stale: see python -m src.api.roles"
