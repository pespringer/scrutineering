"""A failed scan says why in plain words (docs/design/scan-errors.md, step 2).

The digest lookup's errors come from real requests to a local server or a closed port; the
scanners' errors are the recorded ones in fixtures/scanner-errors/.
"""

from __future__ import annotations

import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from src.db.connection import get_session
from src.db.models import Scan
from src.scan import failure
from src.scan.image_identity import parse_image_reference
from src.scan.registry import resolve_digest
from tests.test_scanner_errors import RECORDED

LOCAL = parse_image_reference("registry:5000/shop/api:1.4.2")
HUB = parse_image_reference("scrutineering-nope/private-xyz:1")
PASSWORD = "s3cret-registry-password"


class Registry(BaseHTTPRequestHandler):
    """Answers every manifest request with the status in the path's first segment."""

    def do_HEAD(self):
        status = int(self.path.split("/")[2])
        self.send_response(status)
        if status == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="registry"')
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def registry():
    server = HTTPServer(("127.0.0.1", 0), Registry)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"127.0.0.1:{server.server_port}"
    server.shutdown()


def _lookup(reference: str, scheme: str = "http", credentials=None) -> BaseException:
    with pytest.raises(Exception) as raised:
        resolve_digest(parse_image_reference(reference), scheme=scheme, credentials=credentials)
    return raised.value


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _recorded(scanner: str, case: str) -> str:
    """The `[trivy] …` error step 1 keeps from a recorded run."""
    from src.scan.scanners import grype, trivy
    from src.scan.scanners.base import error_line

    markers = trivy.ERROR_MARKERS if scanner == "trivy" else grype.ERROR_MARKERS
    return f"[{scanner}] " + error_line((RECORDED / f"{scanner}-{case}.stderr").read_text(), markers)


def _both(case: str) -> list[tuple[str, str]]:
    return [("trivy", _recorded("trivy", case)), ("grype", _recorded("grype", case))]


# From the digest lookup


@pytest.mark.parametrize(
    ("status", "credentials", "expected"),
    [
        (404, None, "{reference} isn't in the registry: no such tag or repository."),
        (401, None, "{host} refused to serve {repo} without credentials. It's private, or it doesn't exist."),
        (401, ("bot", PASSWORD), "{host} refused the configured credentials for {repo}, or the repository"),
        (403, ("bot", PASSWORD), "{host} refused the configured credentials for {repo}, or the repository"),
        (429, None, "{host} is limiting pulls. Try again later"),
    ],
)
def test_the_registry_s_status_code_says_why(registry, status, credentials, expected):
    reference = f"{registry}/{status}/app:1.0"
    identity = parse_image_reference(reference)
    error = _lookup(reference, credentials=credentials)
    message = failure.explain(identity, error, [], has_credentials=credentials is not None)
    assert message.startswith(expected.format(reference=reference, host=registry, repo=identity.repo_name))
    assert PASSWORD not in message


def test_a_closed_port_is_unreachable():
    reference = f"127.0.0.1:{_closed_port()}/shop/api:1.4.2"
    assert failure.reason(parse_image_reference(reference), _lookup(reference), []) == (
        f"Couldn't reach the registry 127.0.0.1:{reference.split(':')[1].split('/')[0]} (connection refused). "
        "Check that it's running and that the worker can reach it."
    )


def test_https_to_a_plain_http_registry_needs_registry_insecure(registry):
    reference = f"{registry}/200/app:1.0"
    message = failure.reason(parse_image_reference(reference), _lookup(reference, scheme="https"), [])
    assert (
        message == f"{registry} answers only over plain HTTP. Only the local registry may, with REGISTRY_INSECURE=true."
    )


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        (socket.gaierror(-2, "Name or service not known"), "(no such host)"),
        (TimeoutError("timed out"), "(connection timed out)"),
        (ssl.SSLCertVerificationError(1, "certificate verify failed"), "TLS certificate isn't trusted"),
        (PermissionError("registry requires credentials"), "without credentials"),
        # The same plain-HTTP answer, as other OpenSSL builds word it.
        (ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number"), "answers only over plain HTTP"),
        (ssl.SSLError(1, "[SSL: RECORD_LAYER_FAILURE] record layer failure"), "answers only over plain HTTP"),
    ],
)
def test_other_lookup_failures(reason, expected):
    error = reason if isinstance(reason, PermissionError) else URLError(reason)
    assert expected in failure.reason(LOCAL, error, [])


def test_docker_hub_is_named_as_such():
    assert failure.reason(HUB, PermissionError("registry requires credentials"), []).startswith(
        "Docker Hub refused to serve scrutineering-nope/private-xyz without credentials."
    )


# From the scanners' errors


@pytest.mark.parametrize(
    ("case", "reference", "start"),
    [
        ("refused", "registry:5999/shop/api:1.4.2", "Couldn't reach the registry registry:5999 (connection refused)."),
        (
            "no-such-tag",
            "registry:5000/fixtures/vulnerable-node:no-such-tag",
            "registry:5000/fixtures/vulnerable-node:no",
        ),
        (
            "unauthorized",
            "scrutineering-nope/private-xyz:1",
            "Docker Hub refused to serve scrutineering-nope/private-xyz",
        ),
        ("http-only", "registry:5000/fixtures/vulnerable-node:e2e", "registry:5000 answers only over plain HTTP."),
    ],
)
def test_the_recorded_scanner_errors_say_why(case, reference, start):
    message = failure.explain(parse_image_reference(reference), None, _both(case))
    first, trivy, grype = message.split("\n")
    assert first.startswith(start)
    assert trivy == "trivy: " + _recorded("trivy", case).removeprefix("[trivy] ")
    assert grype.startswith("grype: failed to get image descriptor from registry: ")


def test_a_vulnerability_database_download_isn_t_the_registry():
    errors = [("trivy", '[trivy] init error: DB error: Get "https://mirror.gcr.io/v2/": dial tcp: i/o timeout')]
    assert failure.explain(LOCAL, None, errors).split("\n")[0] == "The scanners failed."


def test_a_local_permission_error_isn_t_the_registry_denying_access():
    errors = [("grype", "[grype] open registry:5000/cache/db: permission denied")]
    assert failure.reason(LOCAL, None, [text for _, text in errors]) is None


def test_a_scanner_timeout_names_the_setting():
    errors = [("trivy", "[trivy] Scan timed out after 600s"), ("grype", "[grype] Scan timed out after 600s")]
    assert failure.explain(LOCAL, None, errors).startswith("The scanners didn't finish within SCANNER_TIMEOUT (600 s).")


def test_a_registry_cause_outranks_a_timeout():
    errors = ["[trivy] Scan timed out after 600s", _recorded("grype", "refused")]
    assert failure.reason(parse_image_reference("registry:5999/x:1"), None, errors).startswith("Couldn't reach")


def test_the_lookup_wins_a_disagreement(registry):
    reference = f"{registry}/404/app:1.0"
    refused = [
        (name, f'[{name}] Get "https://{registry}/v2/": connect: connection refused') for name in ("trivy", "grype")
    ]
    message = failure.explain(parse_image_reference(reference), _lookup(reference), refused)
    assert message.split("\n")[0].endswith("isn't in the registry: no such tag or repository.")
    assert len(message.split("\n")) == 3, "each scanner's line still follows"


def test_an_unknown_error_still_lists_each_scanner():
    assert failure.explain(LOCAL, None, [("trivy", "[trivy] boom"), ("grype", "Unexpected: oops")]) == (
        "The scanners failed.\ntrivy: boom\ngrype: Unexpected: oops"
    )


def test_a_filesystem_scan_has_no_registry():
    assert failure.explain(None, None, _both("refused")).startswith("The scanners failed.\n")


# Where the message is used


def test_a_scan_no_scanner_could_run_stores_the_reason(monkeypatch):
    from src.scan.scanners.base import ScannerError
    from src.scan.tasks import run_scan

    def refused(_scanner, _image, source, *_cache):
        raise ScannerError(source, _recorded(source, "no-such-tag").split("] ", 1)[1])

    with patch("src.scan.tasks.run_scanner_sync", side_effect=refused):
        result = run_scan.run.__func__(MagicMock(), "registry:5000/fixtures/vulnerable-node:no-such-tag", scan_id="r1")
    assert result["status"] == "failed"
    with get_session() as session:
        message = session.query(Scan).filter_by(scan_id="r1").one().error_message
    assert message.split("\n")[0] == (
        "registry:5000/fixtures/vulnerable-node:no-such-tag isn't in the registry: no such tag or repository."
    )
    assert [line.split(":")[0] for line in message.split("\n")[1:]] == ["trivy", "grype"]


def test_required_immutable_identity_says_why_and_that_it_wasn_t_scanned_by_tag(monkeypatch, registry):
    from src.scan.tasks import run_scan

    monkeypatch.setenv("REQUIRE_IMMUTABLE_SCAN_IDENTITY", "true")
    monkeypatch.setenv("LOCAL_REGISTRY_HOST", registry)
    monkeypatch.setenv("REGISTRY_INSECURE", "true")
    monkeypatch.setattr("src.scan.tasks.resolve_digest", resolve_digest)
    reference = f"{registry}/404/app:1.0"
    with patch("src.scan.tasks.run_scanner_sync") as scanner:
        run_scan.run.__func__(MagicMock(), reference, scan_id="r2")
    scanner.assert_not_called()
    with get_session() as session:
        message = session.query(Scan).filter_by(scan_id="r2").one().error_message
    first, second = message.split("\n")
    assert first == f"{reference} isn't in the registry: no such tag or repository."
    assert second.startswith("REQUIRE_IMMUTABLE_SCAN_IDENTITY is set, so it isn't scanned by tag.")


@pytest.mark.parametrize("failed", [("trivy", "grype"), ("grype",)])
def test_a_candidate_that_couldn_t_be_scanned_says_why(monkeypatch, failed):
    from src.scan import inspection, tasks

    def results(names, image, **_kwargs):
        return [(name, "error", _recorded(name, "refused")) if name in failed else (name, "ok", []) for name in names]

    monkeypatch.setattr(tasks, "run_scanners_concurrently", results)
    scan = inspection.inspect_image("registry:5999/shop/api@sha256:" + "a" * 64)
    assert not scan.complete
    lines = scan.error_message.split("\n")
    if len(failed) == 2:
        assert lines[0].startswith("Couldn't reach the registry registry:5999 (connection refused).")
        assert [line.split(":")[0] for line in lines[1:]] == ["trivy", "grype"]
    else:
        assert lines == ["grype: " + _recorded("grype", "refused").removeprefix("[grype] ")]
    assert scan.errors == [line for line in lines if line.startswith(("trivy:", "grype:"))]
