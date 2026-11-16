"""Digest pinning, registry credentials, scanner settings, retries, and the scan schedule."""

import asyncio
import json
import stat
from unittest.mock import MagicMock, patch

import pytest

from src.db.connection import get_session
from src.db.models import Image, Scan
from src.scan.celery_app import scan_schedule
from src.scan.scanners.base import ScannerError, ScannerFinding
from src.scan.scanners.grype import GrypeScanner
from src.scan.scanners.trivy import TrivyScanner
from src.scan.settings import ScannerSettings
from src.scan.models import Severity
from src.scan.tasks import build_scanner, run_scan

DIGEST = "sha256:" + "e" * 64


def _fake_cli(tmp_path, name: str, output: dict):
    """A scanner binary that records its argv and selected env, then prints `output`."""
    log = tmp_path / f"{name}.log"
    script = tmp_path / name
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{log}.args"\n'
        f'env | grep -E "^(TRIVY_|GRYPE_REGISTRY_)" | sort > "{log}.env"\n'
        f"cat <<'JSON'\n{json.dumps(output)}\nJSON\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script), log


def _args(log) -> list[str]:
    return (log.parent / f"{log.name}.args").read_text().split("\n")[:-1]


def _env(log) -> dict[str, str]:
    lines = (log.parent / f"{log.name}.env").read_text().splitlines()
    return dict(line.split("=", 1) for line in lines)


def _finding() -> ScannerFinding:
    return ScannerFinding(
        package_name="openssl",
        package_version="1.1.1",
        package_type="os",
        cve_id="CVE-1",
        title="t",
        description="",
        severity=Severity.HIGH,
        fixed_version="1.1.2",
    )


# -- digest pinning ---------------------------------------------------------


def test_resolved_digest_is_scanned_and_recorded(monkeypatch):
    monkeypatch.setattr("src.scan.tasks.resolve_digest", lambda identity, **kw: DIGEST)
    seen = []

    def scanner(_scanner, image, source):
        seen.append(image)
        return [(_finding(), source)] if source == "trivy" else []

    with patch("src.scan.tasks.run_scanner_sync", side_effect=scanner):
        result = run_scan.run.__func__(MagicMock(), "registry:5000/team/app:1.0", scan_id="d1")

    assert result["status"] == "completed"
    assert seen == [f"registry:5000/team/app@{DIGEST}"] * 2
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id="d1").one()
        assert scan.image_digest == DIGEST
        assert scan.target == "registry:5000/team/app:1.0"
        assert session.query(Image).one().digest == DIGEST


def test_unresolvable_tag_is_scanned_by_tag_by_default():
    seen = []
    with patch("src.scan.tasks.run_scanner_sync", side_effect=lambda _s, image, source: seen.append(image) or []):
        result = run_scan.run.__func__(MagicMock(), "registry:5000/team/app:1.0", scan_id="d2")
    assert result["status"] == "completed"
    assert set(seen) == {"registry:5000/team/app:1.0"}


def test_required_immutable_identity_fails_the_scan_without_scanning(monkeypatch):
    monkeypatch.setenv("REQUIRE_IMMUTABLE_SCAN_IDENTITY", "true")
    with patch("src.scan.tasks.run_scanner_sync") as scanner:
        result = run_scan.run.__func__(MagicMock(), "registry:5000/team/app:1.0", scan_id="d3")
    scanner.assert_not_called()
    assert result["status"] == "failed"
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id="d3").one()
        assert (scan.status, scan.phase) == ("failed", "identity_unresolved")
        assert "could not resolve" in scan.error_message


def test_resolver_gets_host_credentials_and_http_only_for_the_local_registry(monkeypatch):
    calls = []
    monkeypatch.setenv("REGISTRY_INSECURE", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs-test")
    monkeypatch.setattr(
        "src.scan.tasks.resolve_digest", lambda identity, **kw: calls.append((identity.host, kw)) or DIGEST
    )
    with patch("src.scan.tasks.run_scanner_sync", return_value=[]):
        run_scan.run.__func__(MagicMock(), "registry:5000/team/app:1.0", scan_id="h1")
        run_scan.run.__func__(MagicMock(), "ghcr.io/acme/api:v1", scan_id="h2")
    assert calls[0] == ("registry:5000", {"credentials": None, "scheme": "http"})
    assert calls[1] == ("ghcr.io", {"credentials": ("gh_token", "ghs-test"), "scheme": "https"})


def test_partial_credentials_fail_the_scan_with_a_clear_reason(monkeypatch):
    monkeypatch.setenv("DOCKERHUB_USERNAME", "alice")
    monkeypatch.delenv("DOCKERHUB_PASSWORD", raising=False)
    with patch("src.scan.tasks.run_scanner_sync") as scanner:
        result = run_scan.run.__func__(MagicMock(), "alpine:3.20", scan_id="p1")
    scanner.assert_not_called()
    assert result["status"] == "failed"
    with get_session() as session:
        assert (
            "DOCKERHUB_USERNAME and DOCKERHUB_PASSWORD"
            in session.query(Scan).filter_by(scan_id="p1").one().error_message
        )


# -- settings ---------------------------------------------------------------


def test_scanner_settings_are_applied_to_both_scanners(monkeypatch):
    monkeypatch.setenv("SCANNER_TIMEOUT", "1800")
    monkeypatch.setenv("SCANNER_MAX_OUTPUT_BYTES", "1234")
    monkeypatch.setenv("SCANNER_MAX_FINDINGS", "55")
    monkeypatch.setenv("SCANNER_CACHE_DIR", "/var/cache/scrutineering")
    settings = ScannerSettings.from_env()
    trivy = build_scanner("trivy", settings)
    grype = build_scanner("grype", settings)
    assert (trivy.timeout, trivy.max_output_bytes, trivy.max_findings, trivy.cache_dir) == (
        1800,
        1234,
        55,
        "/var/cache/scrutineering",
    )
    assert (grype.timeout, grype.max_output_bytes, grype.max_findings) == (1800, 1234, 55)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SCANNER_TIMEOUT", "soon"),
        ("SCANNER_TIMEOUT", "0"),
        ("SCANNER_RETRY_ATTEMPTS", "-1"),
        ("REQUIRE_IMMUTABLE_SCAN_IDENTITY", "maybe"),
    ],
)
def test_invalid_settings_are_rejected(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name):
        ScannerSettings.from_env()


def test_invalid_setting_fails_the_scan_instead_of_using_a_default(monkeypatch):
    monkeypatch.setenv("SCANNER_TIMEOUT", "soon")
    result = run_scan.run.__func__(MagicMock(), "alpine:3.20", scan_id="bad-setting")
    assert result["status"] == "failed"
    with get_session() as session:
        assert "SCANNER_TIMEOUT" in session.query(Scan).filter_by(scan_id="bad-setting").one().error_message


def test_insecure_transport_is_limited_to_the_local_registry():
    settings = ScannerSettings(registry_insecure=True, local_registry_host="registry:5000")
    assert settings.insecure_host("registry:5000")
    assert settings.insecure_host("localhost:5000")
    assert not settings.insecure_host("ghcr.io")
    assert not ScannerSettings(registry_insecure=False).insecure_host("registry:5000")


# -- retries ----------------------------------------------------------------


def test_transient_scanner_failure_is_retried(monkeypatch):
    monkeypatch.setenv("SCANNER_RETRY_ATTEMPTS", "2")
    attempts = {"trivy": 0}

    def flaky(_scanner, _image, source):
        if source == "trivy":
            attempts["trivy"] += 1
            if attempts["trivy"] < 3:
                raise ScannerError("trivy", "TOOMANYREQUESTS", "")
            return [(_finding(), source)]
        return []

    with patch("src.scan.tasks.run_scanner_sync", side_effect=flaky):
        result = run_scan.run.__func__(MagicMock(), "alpine:3.20", scan_id="r1")
    assert attempts["trivy"] == 3
    assert result["status"] == "completed"
    assert result["findings"] == 1


def test_retries_are_bounded(monkeypatch):
    monkeypatch.setenv("SCANNER_RETRY_ATTEMPTS", "1")
    calls = []

    def always_down(_scanner, _image, source):
        calls.append(source)
        raise ScannerError(source, "down", "")

    with patch("src.scan.tasks.run_scanner_sync", side_effect=always_down):
        result = run_scan.run.__func__(MagicMock(), "alpine:3.20", scan_id="r2")
    assert result["status"] == "failed"
    assert sorted(calls) == ["grype", "grype", "trivy", "trivy"]


# -- scanner command lines --------------------------------------------------


def test_trivy_passes_credentials_through_env_and_never_adds_a_secret_flag(tmp_path):
    cmd, log = _fake_cli(tmp_path, "trivy", {"Results": []})
    scanner = TrivyScanner(trivy_cmd=cmd, registry_username="bot", registry_password="pw", insecure=True)
    assert asyncio.run(scanner.scan(f"registry:5000/team/app@{DIGEST}")) == []
    args = _args(log)
    assert args[0] == "image"
    assert "--secret" not in args
    assert "--insecure" in args
    assert args[-1] == f"registry:5000/team/app@{DIGEST}"
    assert _env(log) == {"TRIVY_PASSWORD": "pw", "TRIVY_USERNAME": "bot"}


def test_trivy_without_credentials_or_insecure_flag(tmp_path):
    cmd, log = _fake_cli(tmp_path, "trivy", {"Results": []})
    asyncio.run(TrivyScanner(trivy_cmd=cmd).scan("alpine:3.20"))
    assert "--insecure" not in _args(log)
    assert _env(log) == {}


def test_grype_passes_credentials_and_local_registry_transport_through_env(tmp_path):
    cmd, log = _fake_cli(tmp_path, "grype", {"matches": []})
    scanner = GrypeScanner(
        grype_cmd=cmd,
        registry_username="bot",
        registry_password="pw",
        registry_authority="registry:5000",
        insecure=True,
    )
    asyncio.run(scanner.scan("registry:5000/team/app:1.0"))
    assert _args(log)[-1] == "registry:registry:5000/team/app:1.0"
    assert _env(log) == {
        "GRYPE_REGISTRY_AUTH_AUTHORITY": "registry:5000",
        "GRYPE_REGISTRY_AUTH_PASSWORD": "pw",
        "GRYPE_REGISTRY_AUTH_USERNAME": "bot",
        "GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY": "true",
        "GRYPE_REGISTRY_INSECURE_USE_HTTP": "true",
    }


def test_inherited_insecure_settings_do_not_leak_into_remote_scans(tmp_path, monkeypatch):
    monkeypatch.setenv("GRYPE_REGISTRY_INSECURE_USE_HTTP", "true")
    monkeypatch.setenv("TRIVY_INSECURE", "true")
    grype_cmd, grype_log = _fake_cli(tmp_path, "grype", {"matches": []})
    trivy_cmd, trivy_log = _fake_cli(tmp_path, "trivy", {"Results": []})
    asyncio.run(GrypeScanner(grype_cmd=grype_cmd).scan("ghcr.io/acme/api:v1"))
    asyncio.run(TrivyScanner(trivy_cmd=trivy_cmd).scan("ghcr.io/acme/api:v1"))
    assert {k: v for k, v in _env(grype_log).items() if k.startswith("GRYPE_")} == {}
    assert {k: v for k, v in _env(trivy_log).items() if k.startswith("TRIVY_")} == {}


def test_grype_enforces_the_finding_limit(tmp_path):
    match = {
        "vulnerability": {"id": "CVE-1", "severity": "High", "fix": {"versions": []}},
        "artifact": {"name": "openssl", "version": "1", "type": "deb"},
    }
    cmd, _ = _fake_cli(
        tmp_path, "grype", {"matches": [match, {**match, "vulnerability": {**match["vulnerability"], "id": "CVE-2"}}]}
    )
    with pytest.raises(ScannerError, match="finding count"):
        asyncio.run(GrypeScanner(grype_cmd=cmd, max_findings=1).scan("alpine:3.20"))


# -- schedule ---------------------------------------------------------------


def test_scan_schedule_reads_schedule_cron_scan():
    schedule = scan_schedule("30 2 * * 1")
    assert (schedule._orig_minute, schedule._orig_hour, schedule._orig_day_of_week) == ("30", "2", "1")
    assert str(scan_schedule("")) == str(scan_schedule("0 */6 * * *"))
    with pytest.raises(ValueError, match="five cron fields"):
        scan_schedule("every six hours")
