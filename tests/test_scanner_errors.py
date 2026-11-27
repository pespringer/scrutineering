"""A failed scanner's error is the line that names the cause (docs/design/scan-errors.md, step 1).

The fake scanners replay stderr recorded from the real ones (fixtures/scanner-errors/README.md).
"""

from __future__ import annotations

import asyncio
import stat
from pathlib import Path

import pytest

from src.scan.scanners.base import MAX_ERROR, ScannerError, error_line
from src.scan.scanners.grype import GrypeScanner
from src.scan.scanners.trivy import TrivyScanner

RECORDED = Path(__file__).resolve().parents[1] / "fixtures" / "scanner-errors"
REFUSED = (
    'Get "https://registry:5999/v2/": dial tcp 172.19.0.5:5999: connect: connection refused; '
    'Get "http://registry:5999/v2/": dial tcp 172.19.0.5:5999: connect: connection refused'
)
NO_SUCH_TAG = (
    "GET http://registry:5000/v2/fixtures/vulnerable-node/manifests/no-such-tag: "
    "MANIFEST_UNKNOWN: manifest unknown; unknown tag=no-such-tag"
)
UNAUTHORIZED = (
    "GET https://index.docker.io/v2/scrutineering-nope/private-xyz/manifests/1: UNAUTHORIZED: "
    "authentication required; [map[Action:pull Class: Name:scrutineering-nope/private-xyz Type:repository]]"
)
HTTP_ONLY = 'Get "https://registry:5000/v2/": http: server gave HTTP response to HTTPS client'


def _fake(tmp_path: Path, name: str, recording: str, code: int, stdout: str = "") -> str:
    """A scanner that writes a recorded stderr, prints `stdout` and exits with `code`."""
    (tmp_path / "stdout").write_text(stdout)
    path = tmp_path / name
    path.write_text(
        f'#!/bin/sh\necho "$@" > {tmp_path}/args\ncat {tmp_path}/stdout\ncat {RECORDED / recording} >&2\nexit {code}\n'
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def _trivy(tmp_path: Path, recording: str, code: int = 1, stdout: str = "") -> TrivyScanner:
    return TrivyScanner(trivy_cmd=_fake(tmp_path, "trivy", recording, code, stdout))


def _grype(tmp_path: Path, recording: str, code: int = 1, stdout: str = "") -> GrypeScanner:
    return GrypeScanner(grype_cmd=_fake(tmp_path, "grype", recording, code, stdout))


def _error(scanner, image: str = "registry:5000/shop/api:1.4.2") -> str:
    with pytest.raises(ScannerError) as raised:
        asyncio.run(scanner.scan(image))
    return str(raised.value)


@pytest.mark.parametrize(
    ("case", "cause"),
    [("refused", REFUSED), ("no-such-tag", NO_SUCH_TAG), ("unauthorized", UNAUTHORIZED), ("http-only", HTTP_ONLY)],
)
def test_each_scanner_reports_the_registry_s_answer(tmp_path, case, cause):
    trivy = _error(_trivy(tmp_path, f"trivy-{case}.stderr"))
    grype = _error(_grype(tmp_path, f"grype-{case}.stderr"))
    assert trivy == f"[trivy] {cause}"
    assert grype == f"[grype] failed to get image descriptor from registry: {cause}"


def test_trivy_exit_code_1_is_a_failure_even_with_json_on_stdout(tmp_path):
    """Trivy exits 0 whatever it finds; exit 1 used to be parsed as a result with no findings."""
    assert _error(_trivy(tmp_path, "trivy-refused.stderr", stdout='{"Results": []}')) == f"[trivy] {REFUSED}"


def test_a_successful_scan_ignores_the_scanners_warnings(tmp_path):
    assert asyncio.run(_trivy(tmp_path, "trivy-findings.stderr", 0, '{"Results": []}').scan("alpine:3.20")) == []
    assert asyncio.run(_grype(tmp_path, "grype-findings.stderr", 0, '{"matches": []}').scan("alpine:3.20")) == []


def test_grype_runs_without_quiet_which_hides_its_errors(tmp_path):
    asyncio.run(_grype(tmp_path, "grype-findings.stderr", 0, '{"matches": []}').scan("alpine:3.20"))
    assert (tmp_path / "args").read_text().split() == ["-o", "json", "alpine:3.20"]


def test_an_exit_of_0_with_no_json_still_fails(tmp_path):
    assert "Failed to parse JSON output" in _error(_trivy(tmp_path, "trivy-findings.stderr", 0))


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("2026-11-27T03:46:22Z\tFATAL\tFatal error\trun error: image scan error: boom", "image scan error: boom"),
        (
            "2026-11-27T03:46:22Z\tFATAL\tFatal error\tinit error: DB error: failed to download",
            "init error: DB error: failed to download",
        ),
        ("progress\nlast words\n\n", "last words"),
        ("", "no error output"),
        ("remote error: " + "x" * 600, "x" * MAX_ERROR),
    ],
)
def test_without_a_registry_answer_the_fatal_error_or_last_line_is_kept(stderr, expected):
    from src.scan.scanners.trivy import ERROR_MARKERS

    assert error_line(stderr, ERROR_MARKERS) == expected


def test_grype_falls_back_to_its_first_error_line():
    from src.scan.scanners.grype import ERROR_MARKERS

    stderr = "[0000]  WARN registry communication is insecure\n[0001] ERROR failed to load vulnerability db\n"
    assert error_line(stderr, ERROR_MARKERS) == "failed to load vulnerability db"


def test_the_registry_password_never_appears_in_the_error(tmp_path):
    scanner = TrivyScanner(
        trivy_cmd=_fake(tmp_path, "trivy", "trivy-unauthorized.stderr", 1),
        registry_username="bot",
        registry_password="s3cret-registry-password",
    )
    assert "s3cret-registry-password" not in _error(scanner)
