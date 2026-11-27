"""Why a scan failed, in one plain sentence (docs/design/scan-errors.md).

The digest lookup's exception is asked first: it came straight from the registry, with a status
code. Otherwise the scanners' own errors are matched against what Trivy and Grype print. The
host, repository and reference in the sentence come from the parsed image identity, never from
the error text, which is written by whoever runs the registry.
"""

from __future__ import annotations

import re
import socket
import ssl
from urllib.error import HTTPError, URLError

from src.scan.image_identity import ImageIdentity, ImageRegistry

# What the scanners print. Network phrases are matched lower-cased; registry error codes exactly,
# so a local "permission denied" is never read as the registry's `DENIED`.
CONNECT = ("connection refused", "no such host", "i/o timeout", "connection timed out", "network is unreachable")
HTTP_ONLY = "server gave http response to https client"
UNTRUSTED = ("x509:", "certificate verify failed")
NOT_FOUND = ("MANIFEST_UNKNOWN", "NAME_UNKNOWN")
RATE_LIMITED = ("TOOMANYREQUESTS",)
UNAUTHORIZED = ("UNAUTHORIZED",)
DENIED = ("DENIED",)
# How OpenSSL reports a plain-HTTP answer to a TLS handshake; the wording depends on its build.
PLAIN_HTTP_TLS = ("wrong_version_number", "record_layer_failure")
TIMED_OUT = re.compile(r"timed out after (\d+)s")
ERROR_PREFIX = re.compile(r"^\[(\w+)\] ")


def _where(identity: ImageIdentity | None) -> tuple[str, str, str]:
    if identity is None:
        return "the registry", "the image", "the image"
    host = "Docker Hub" if identity.registry == ImageRegistry.DOCKER_HUB else identity.host
    return host, identity.repo_name, identity.reference


def _sentence(cause: str, detail: str, identity: ImageIdentity | None, has_credentials: bool) -> str:
    host, repository, reference = _where(identity)
    if cause == "connect":
        return (
            f"Couldn't reach the registry {host} ({detail}). Check that it's running and that the worker can reach it."
        )
    if cause == "http_only":
        return f"{host} answers only over plain HTTP. Only the local registry may, with REGISTRY_INSECURE=true."
    if cause == "untrusted":
        return f"{host}'s TLS certificate isn't trusted by the worker."
    if cause in ("unauthorized", "denied") and not has_credentials:
        return (
            f"{host} refused to serve {repository} without credentials. It's private, or it doesn't exist. "
            "Add credentials (REGISTRY_CREDENTIALS_JSON, or DOCKERHUB_USERNAME for Docker Hub)."
        )
    if cause in ("unauthorized", "denied"):
        return f"{host} refused the configured credentials for {repository}, or the repository doesn't exist."
    if cause == "not_found":
        return f"{reference} isn't in the registry: no such tag or repository."
    if cause == "rate_limited":
        return f"{host} is limiting pulls. Try again later; Docker Hub allows more with DOCKERHUB_USERNAME."
    return f"The scanners didn't finish within SCANNER_TIMEOUT ({detail} s)."


def _from_lookup(error: BaseException | None) -> tuple[str, str] | None:
    """The cause the digest lookup's exception shows, or None if it shows none."""
    if isinstance(error, HTTPError):
        return {401: ("unauthorized", ""), 403: ("denied", ""), 404: ("not_found", ""), 429: ("rate_limited", "")}.get(
            error.code
        )
    if isinstance(error, PermissionError):
        return "unauthorized", ""
    reason = error.reason if isinstance(error, URLError) else error
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "untrusted", ""
    if isinstance(reason, ssl.SSLError) and any(
        phrase in str(reason).lower().replace(" ", "_") for phrase in PLAIN_HTTP_TLS
    ):
        return "http_only", ""
    if isinstance(reason, ConnectionRefusedError):
        return "connect", "connection refused"
    if isinstance(reason, socket.gaierror):
        return "connect", "no such host"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "connect", "connection timed out"
    if isinstance(reason, OSError) and isinstance(error, URLError):
        return "connect", str(reason)[:80]
    return None


def _hosts(identity: ImageIdentity) -> tuple[str, ...]:
    """How the image's registry appears in the scanners' URLs."""
    if identity.registry == ImageRegistry.DOCKER_HUB:
        return ("docker.io",)
    return (identity.host.lower(),)


def _from_text(identity: ImageIdentity | None, errors: list[str]) -> tuple[str, str] | None:
    """The cause the scanners' errors show, most specific first.

    Registry causes count only in an error that names the image's registry, so a scanner that
    couldn't download its vulnerability database isn't reported as the registry being down.
    """
    cause = _registry_cause(identity, errors) if identity is not None else None
    if cause is None and (match := TIMED_OUT.search("\n".join(errors))):
        return "timed_out", match.group(1)
    return cause


def _registry_cause(identity: ImageIdentity, errors: list[str]) -> tuple[str, str] | None:
    about = [error for error in errors if any(host in error.lower() for host in _hosts(identity))]
    lowered = "\n".join(about).lower()
    exact = "\n".join(about)
    if HTTP_ONLY in lowered:
        return "http_only", ""
    for phrase in CONNECT:
        if phrase in lowered:
            return "connect", phrase
    checks = (
        (UNTRUSTED, lowered, "untrusted"),
        (NOT_FOUND, exact, "not_found"),
        (RATE_LIMITED, exact, "rate_limited"),
        (UNAUTHORIZED, exact, "unauthorized"),
        (DENIED, exact, "denied"),
    )
    for phrases, text, cause in checks:
        if any(phrase in text for phrase in phrases):
            return cause, ""
    return None


def reason(
    identity: ImageIdentity | None,
    lookup_error: BaseException | None,
    scanner_errors: list[str],
    *,
    has_credentials: bool = False,
) -> str | None:
    """The plain sentence, or None when neither source shows a known cause."""
    cause = _from_lookup(lookup_error) if lookup_error is not None else None
    cause = cause or _from_text(identity, scanner_errors)
    return _sentence(*cause, identity, has_credentials) if cause else None


def scanner_lines(errors: list[tuple[str, str]]) -> list[str]:
    """`trivy: …` for each failed scanner, without the `[trivy] ` its error starts with."""
    return [f"{name}: {ERROR_PREFIX.sub('', text, count=1)}" for name, text in errors]


def explain(
    identity: ImageIdentity | None,
    lookup_error: BaseException | None,
    errors: list[tuple[str, str]],
    *,
    has_credentials: bool = False,
) -> str:
    """A failed scan's `error_message`: the reason, then each scanner's own line."""
    first = reason(identity, lookup_error, [text for _, text in errors], has_credentials=has_credentials)
    return "\n".join([first or "The scanners failed.", *scanner_lines(errors)])


def unresolved(identity: ImageIdentity, lookup_error: BaseException, *, has_credentials: bool = False) -> str:
    """The `error_message` of a scan stopped because its tag has no digest and identity must be immutable."""
    first = reason(identity, lookup_error, [], has_credentials=has_credentials)
    return "\n".join(
        [
            first or f"Couldn't resolve {identity.reference} to a digest.",
            "REQUIRE_IMMUTABLE_SCAN_IDENTITY is set, so it isn't scanned by tag. "
            f"The lookup: could not resolve {identity.reference} to a digest: {str(lookup_error)[:300]}",
        ]
    )
