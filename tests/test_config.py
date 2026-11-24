"""src/config.py is the only place settings are read, and docs/CONFIGURATION.md describes it."""

import ast
import re
from pathlib import Path

import pytest

from src.config import documentation, get_settings, variable_names

ROOT = Path(__file__).resolve().parents[1]
# Process environment handed on to subprocesses (git, npm, scanners), not settings.
PASS_THROUGH = {"PATH", "HOME", "LANG", "HTTPS_PROXY", "NO_PROXY"}


def test_configuration_doc_is_generated_from_the_settings_module():
    assert (ROOT / "docs" / "CONFIGURATION.md").read_text() == documentation(), (
        "docs/CONFIGURATION.md is stale: run `python -m src.config > docs/CONFIGURATION.md`"
    )


def _environment_reads(tree: ast.AST):
    """(line, name) for each os.environ / os.getenv access; name is None when not a literal."""
    for node in ast.walk(tree):
        target = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            owner = node.func.value
            is_environ = isinstance(owner, ast.Attribute) and owner.attr == "environ"
            if (is_environ and node.func.attr == "get") or node.func.attr == "getenv":
                target = node.args[0] if node.args else None
            elif is_environ and node.func.attr == "items":
                yield node.lineno, "*"
                continue
            else:
                continue
        elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
            target = node.slice
        else:
            continue
        yield node.lineno, target.value if isinstance(target, ast.Constant) else None


def test_settings_are_read_only_in_src_config():
    offenders = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        if relative == "src/config.py" or "/migrations/" in relative:
            continue
        for line, name in _environment_reads(ast.parse(path.read_text())):
            if name in PASS_THROUGH or name == "*":
                continue
            offenders.append(f"{relative}:{line} reads {name or 'a computed name'}")
    assert not offenders, "read settings through src.config.get_settings():\n" + "\n".join(offenders)


def _assigned_names(text: str) -> set[str]:
    return set(re.findall(r"^([A-Z][A-Z0-9_]*)=", text, re.MULTILINE))


def test_every_configured_variable_is_documented():
    documented = variable_names()
    example = _assigned_names((ROOT / ".env.example").read_text())
    assert not example - documented, f".env.example sets undocumented variables: {sorted(example - documented)}"

    # `$${...}` is Compose's escape for a literal `${...}`, not a variable.
    compose = set(re.findall(r"(?<!\$)\$\{([A-Z][A-Z0-9_]*)", (ROOT / "docker-compose.yml").read_text()))
    compose.discard("PLANNER_API_KEY")  # the old name of PYTHON_API_KEY, still accepted by Compose
    assert not compose - documented, f"docker-compose.yml uses undocumented variables: {sorted(compose - documented)}"

    manifests = set()
    for path in (ROOT / "k8s").glob("*.yaml"):
        manifests |= set(re.findall(r"^\s+([A-Z][A-Z0-9_]+):\s", path.read_text(), re.MULTILINE))
        manifests |= set(re.findall(r"-\s+name:\s+([A-Z][A-Z0-9_]+)\s*$", path.read_text(), re.MULTILINE))
    assert not manifests - documented, f"k8s manifests set undocumented variables: {sorted(manifests - documented)}"


def test_invalid_values_are_rejected_by_variable_name():
    with pytest.raises(ValueError, match="SCANNER_TIMEOUT"):
        get_settings({"SCANNER_TIMEOUT": "soon"})
    with pytest.raises(ValueError, match="SCANNER_CACHE_BACKEND"):
        get_settings({"SCANNER_CACHE_BACKEND": "disk"})
    with pytest.raises(ValueError, match="REGISTRY_CREDENTIALS_JSON"):
        get_settings({"REGISTRY_CREDENTIALS_JSON": "[]"})


def test_empty_values_mean_the_default_and_lists_split_on_commas():
    settings = get_settings({"SCANNER_TIMEOUT": "", "DASHBOARD_DEFAULT_ROLES": "dashboard, remediator,"})
    assert settings.scanner_timeout == 600
    assert settings.dashboard_default_roles == ["dashboard", "remediator"]


def test_environment_changes_are_seen_and_secrets_stay_masked(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-secret-value")
    settings = get_settings()
    assert settings.github_token.get_secret_value() == "ghp-secret-value"
    assert "ghp-secret-value" not in repr(settings)
    monkeypatch.setenv("GITHUB_TOKEN", "")
    assert get_settings().github_token.get_secret_value() == ""
