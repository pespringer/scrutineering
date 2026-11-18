"""Applying planned fixes to a checked-out source."""

import io
import json
import os
import stat
import sys
from pathlib import Path
from urllib.error import HTTPError

import pytest

from src.remediation.apply import (
    ApplyError,
    Checkout,
    apply_action,
    bump_base_image,
    newer_tag,
    update_npm,
    update_pip,
    upgrade_os_packages,
)
from src.scan.image_identity import parse_image_reference
from src.scan.registry import list_tags


def _checkout(tmp_path: Path, dockerfile: str = "FROM node:18.12-alpine\nUSER node\n") -> Checkout:
    (tmp_path / "Dockerfile").write_text(dockerfile)
    return Checkout(root=tmp_path, dockerfile=tmp_path / "Dockerfile", context=tmp_path)


@pytest.fixture
def npm_log(tmp_path, monkeypatch):
    """A fake npm that records each invocation and its working directory."""
    log = tmp_path / "npm.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "npm"
    script.write_text(
        f"#!{sys.executable}\nimport os, sys\n"
        f"open({str(log)!r}, 'a').write(os.getcwd() + ' ' + ' '.join(sys.argv[1:]) + '\\n')\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return log


def test_direct_npm_dependency_is_reinstalled_at_the_fixed_version(tmp_path, npm_log):
    (tmp_path / "repo").mkdir()
    source = _checkout(tmp_path / "repo")
    (source.root / "package.json").write_text(json.dumps({"devDependencies": {"lodash": "4.17.20"}}))
    assert update_npm(source, "lodash", "4.17.21") == ["."]
    call = npm_log.read_text()
    assert "install lodash@4.17.21 --save-dev --save-exact --package-lock-only --ignore-scripts" in call


def test_transitive_npm_dependency_gets_an_override(tmp_path, npm_log):
    (tmp_path / "repo" / "app").mkdir(parents=True)
    source = _checkout(tmp_path / "repo")
    app = source.root / "app"
    (app / "package.json").write_text(json.dumps({"dependencies": {"express": "4.0.0"}}))
    (app / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/qs": {"version": "6.0.0"}}}))
    (source.root / "node_modules" / "x").mkdir(parents=True)
    (source.root / "node_modules" / "x" / "package.json").write_text(json.dumps({"dependencies": {"qs": "1"}}))

    assert update_npm(source, "qs", "6.10.3") == ["app"]
    assert json.loads((app / "package.json").read_text())["overrides"] == {"qs": "6.10.3"}
    assert npm_log.read_text().strip().endswith("install --package-lock-only --ignore-scripts --no-audit --no-fund")


def test_npm_update_fails_when_the_package_is_not_in_the_source(tmp_path, npm_log):
    source = _checkout(tmp_path)
    (tmp_path / "package.json").write_text("{}")
    with pytest.raises(ApplyError, match="not in any package.json"):
        update_npm(source, "lodash", "4.17.21")
    with pytest.raises(ApplyError, match="unusual"):
        update_npm(source, "lodash; rm -rf /", "1")


def test_pip_pins_are_rewritten_with_name_normalisation(tmp_path):
    source = _checkout(tmp_path)
    (tmp_path / "requirements.txt").write_text("Django==4.2.1\nsome_pkg[extra] == 1.0  # pinned\nflask>=2\n")
    assert update_pip(source, "some-pkg", "1.2") == ["requirements.txt"]
    assert update_pip(source, "django", "4.2.11") == ["requirements.txt"]
    assert (tmp_path / "requirements.txt").read_text() == "Django==4.2.11\nsome_pkg[extra]==1.2  # pinned\nflask>=2\n"
    with pytest.raises(ApplyError, match="not pinned"):
        update_pip(source, "flask", "3.0")


def test_os_packages_are_upgraded_in_the_final_stage(tmp_path):
    source = _checkout(tmp_path, "FROM golang:1.22 AS build\nRUN go build\nFROM alpine:3.18\nUSER app\n")
    upgrade_os_packages(source, "apk", {"libssl3": "3.1.4-r0", "libcrypto3": "3.1.4-r0"})
    lines = source.dockerfile.read_text().splitlines()
    assert lines[2] == "FROM alpine:3.18"
    assert lines[4] == "RUN apk add --no-cache --upgrade libcrypto3 libssl3"
    assert lines[5] == "USER app"
    with pytest.raises(ApplyError):
        upgrade_os_packages(source, "pacman", {"x": "1"})


@pytest.mark.parametrize(
    ("current", "tags", "expected"),
    [
        ("18.12-alpine", ["18.12-alpine", "18.20-alpine", "18.20", "19.1-alpine", "18.3-alpine"], "18.20-alpine"),
        ("3.11.4-slim", ["3.11.9-slim", "3.12.1-slim", "3.11.10-slim"], "3.11.10-slim"),
        ("1.25", ["1.25", "1.27", "2.0", "1.27-alpine", "latest"], "1.27"),
        ("18.20-alpine", ["18.12-alpine"], None),
        ("latest", ["1.0"], None),
    ],
)
def test_newer_tag_stays_in_the_same_release_line(current, tags, expected):
    assert newer_tag(current, tags) == expected


def test_base_image_bump_rewrites_the_final_from_line(tmp_path):
    source = _checkout(tmp_path, "FROM --platform=linux/amd64 node:18.12-alpine AS runtime\nUSER node\n")
    files, old, new = bump_base_image(source, lambda repository: ["18.20-alpine", "20.1-alpine"])
    assert (old, new) == ("node:18.12-alpine", "node:18.20-alpine")
    assert source.dockerfile.read_text().splitlines()[0] == "FROM --platform=linux/amd64 node:18.20-alpine AS runtime"
    assert files == ["Dockerfile"]


@pytest.mark.parametrize(
    "dockerfile", ["FROM ${BASE}\n", "FROM node@sha256:" + "a" * 64 + "\n", "FROM node:20 AS a\nFROM a\n"]
)
def test_base_image_bump_refuses_what_it_cannot_rewrite(tmp_path, dockerfile):
    with pytest.raises(ApplyError):
        bump_base_image(_checkout(tmp_path, dockerfile), lambda repository: ["99"])


def test_unknown_strategy_is_refused(tmp_path):
    with pytest.raises(ApplyError):
        apply_action(_checkout(tmp_path), {"strategy": "custom"}, lambda repository: [])


class _Response(io.BytesIO):
    def __init__(self, body: dict, link: str = ""):
        super().__init__(json.dumps(body).encode())
        self.headers = {"Link": link} if link else {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_tags_are_listed_across_pages_after_a_token_challenge():
    calls = []

    def opener(request, timeout):
        calls.append((request.full_url, request.headers.get("Authorization")))
        if "auth.example" in request.full_url:
            return _Response({"token": "t"})
        if request.headers.get("Authorization") is None:
            raise HTTPError(
                request.full_url, 401, "", {"WWW-Authenticate": 'Bearer realm="https://auth.example/token"'}, None
            )
        if "last=" in request.full_url:
            return _Response({"tags": ["18.20-alpine"]})
        return _Response({"tags": ["18.12-alpine"]}, link='</v2/library/node/tags/list?n=1000&last=x>; rel="next"')

    tags = list_tags(parse_image_reference("node:18"), opener=opener)
    assert tags == ["18.12-alpine", "18.20-alpine"]
    assert calls[-1] == ("https://registry-1.docker.io/v2/library/node/tags/list?n=1000&last=x", "Bearer t")


def test_the_test_stage_extends_the_final_stage():
    from src.remediation.build import test_dockerfile

    single = test_dockerfile("FROM node:18-alpine\nCOPY . .\n", ["npm", "test"])
    assert single.splitlines() == [
        "FROM node:18-alpine AS scrutineering-candidate",
        "COPY . .",
        "",
        "FROM scrutineering-candidate AS scrutineering-test",
        'RUN ["npm", "test"]',
    ]
    staged = test_dockerfile(
        "# syntax=docker/dockerfile:1\nFROM golang:1.22 AS build\nRUN go build\n"
        "FROM --platform=linux/amd64 alpine:3.20 AS runtime\nCOPY --from=build /app /app\n",
        ["/app", "--self-test"],
    )
    assert staged.startswith("# syntax=docker/dockerfile:1\nFROM golang:1.22 AS build\n")
    assert "FROM --platform=linux/amd64 alpine:3.20 AS runtime\n" in staged
    assert staged.endswith('FROM runtime AS scrutineering-test\nRUN ["/app", "--self-test"]\n')
