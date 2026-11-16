"""Execute an approved remediation: patch the source, build a candidate image, and verify it by scanning.

    building:  clone the image's source, apply each planned action, record the patch,
               build the candidate with BuildKit and push it to the local registry
    verifying: scan the candidate with the same scanners; the targeted vuln_keys must be gone
    → ready             nothing new at critical/high
    → needs_acceptance  new critical/high findings (decision D6); an operator decides
    → failed            any step failed; `error_message` says which and why

The server decides every outcome from what it checked out, built, and scanned itself.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from celery import shared_task

from src.db.connection import get_session
from src.db.models import Image, Remediation, RemediationStatus, ScanFinding
from src.db.repositories import RemediationRepository
from src.remediation.apply import ApplyError, apply_action
from src.remediation.build import BuildError, BuiltImage, build_and_push, checkout, diff
from src.remediation.sources import SourceError, settings_from_record
from src.scan.image_identity import parse_image_reference
from src.scan.inspection import inspect_image
from src.scan.registry import credentials_for_host, list_tags
from src.scan.settings import ScannerSettings
from src.scan.utils.db import make_vuln_key

logger = logging.getLogger(__name__)

MAX_PATCH_BYTES = 200_000
BLOCKING_SEVERITIES = {"critical", "high"}
RUNNING = {RemediationStatus.BUILDING, RemediationStatus.VERIFYING}


class RemediationStopped(Exception):
    """The remediation left `building`/`verifying` while running (for example, it was cancelled)."""


def candidate_reference(image: Image, remediation_id: int) -> str:
    """Where the candidate is pushed: the image's repository path, in the local registry."""
    repository = parse_image_reference(image.full_name).repository
    registry = ScannerSettings.from_env().local_registry_host
    return f"{registry}/{repository}:scrutineering-candidate-{remediation_id}"


def registry_tags(image: str) -> list[str]:
    """Tags of a base image, for base-image bumps. Uses the scan credentials for its registry."""
    identity = parse_image_reference(image)
    scheme = "http" if ScannerSettings.from_env().insecure_host(identity.host) else "https"
    return list_tags(identity, credentials=credentials_for_host(identity.host), scheme=scheme)


def verdict(targets: set[str], baseline: set[str], findings: list[dict]) -> dict:
    """Compare the candidate's findings with the targets and with what the image already had."""

    def key(item: dict) -> str:
        return make_vuln_key(item.get("cve_id") or "", item["package_name"])

    new_blocking = [
        {
            "cve_id": item.get("cve_id"),
            "package_name": item["package_name"],
            "package_version": item.get("package_version"),
            "severity": str(item.get("severity") or "").lower(),
        }
        for item in findings
        if str(item.get("severity") or "").lower() in BLOCKING_SEVERITIES and key(item) not in baseline
    ]
    return {
        "targeted": len(targets),
        "still_present": sorted(targets & {key(item) for item in findings}),
        "new_critical_or_high": sorted(new_blocking, key=lambda item: (item["cve_id"] or "", item["package_name"])),
        "candidate_findings": len(findings),
    }


def _advance(remediation_id: int, expected: RemediationStatus, target: RemediationStatus, **values) -> None:
    """Record `values` and move to `target`, unless someone else changed the status meanwhile."""
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None or remediation.status != expected:
            raise RemediationStopped(remediation.status.value if remediation else "deleted")
        for name, value in values.items():
            setattr(remediation, name, value)
        if target != expected:
            RemediationRepository.update_status(session, remediation_id, target)


def _event(remediation_id: int, event_type: str, detail: dict) -> None:
    with get_session() as session:
        RemediationRepository.record_event(session, remediation_id, event_type, detail)


def _fail(remediation_id: int, reason: str) -> dict:
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is not None and remediation.status in RUNNING:
            RemediationRepository.update_status(
                session, remediation_id, RemediationStatus.FAILED, error_message=reason[:4000]
            )
            RemediationRepository.record_event(session, remediation_id, "failed", {"reason": reason[:1000]})
    return {"remediation_id": remediation_id, "status": "failed", "reason": reason}


def _load(remediation_id: int) -> dict:
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise RemediationStopped("deleted")
        if remediation.status != RemediationStatus.BUILDING:
            raise RemediationStopped(remediation.status.value)
        image = remediation.image
        if image.source is None:
            raise SourceError("the image has no connected source")
        open_keys = session.query(ScanFinding.vuln_key).filter(
            ScanFinding.image_id == image.id, ScanFinding.resolved_at.is_(None)
        )
        return {
            "settings": settings_from_record(image.source),
            "actions": [dict(action.detail or {}) for action in remediation.actions],
            "targets": {finding.vuln_key for finding in remediation.findings},
            "baseline": {vuln_key for (vuln_key,) in open_keys},
            "candidate": candidate_reference(image, remediation_id),
        }


def _patch_and_build(remediation_id: int, job: dict) -> BuiltImage:
    with tempfile.TemporaryDirectory(prefix="scrutineering-remediation-") as workdir:
        source, commit = checkout(job["settings"], Path(workdir))
        applied = [apply_action(source, detail, registry_tags) for detail in job["actions"]]
        patch = diff(source)
        if not patch.strip():
            raise ApplyError("the actions changed nothing in the source")
        _advance(
            remediation_id,
            RemediationStatus.BUILDING,
            RemediationStatus.BUILDING,
            source_commit=commit,
            patch=patch[:MAX_PATCH_BYTES],
        )
        _event(remediation_id, "patched", {"commit": commit, "applied": applied})
        return build_and_push(source, job["settings"].build_args, job["candidate"])


def run_remediation(remediation_id: int) -> dict:
    """Run one remediation from `building` to a resting status. Every exit leaves it out of `building`."""
    try:
        job = _load(remediation_id)
        built = _patch_and_build(remediation_id, job)
        _advance(
            remediation_id,
            RemediationStatus.BUILDING,
            RemediationStatus.VERIFYING,
            candidate_image=built.reference,
            candidate_digest=built.digest,
        )
        _event(remediation_id, "built", {"candidate": built.reference, "digest": built.digest})

        scan = inspect_image(f"{built.reference.rsplit(':', 1)[0]}@{built.digest}")
        if not scan.complete:
            raise BuildError("the candidate scan did not complete: " + "; ".join(scan.errors)[:1500])
        result = verdict(job["targets"], job["baseline"], scan.findings)
        if result["still_present"]:
            _advance(remediation_id, RemediationStatus.VERIFYING, RemediationStatus.VERIFYING, verification=result)
            count = len(result["still_present"])
            return _fail(remediation_id, f"the patched image still has {count} of the targeted findings")
        outcome = RemediationStatus.NEEDS_ACCEPTANCE if result["new_critical_or_high"] else RemediationStatus.READY
        _advance(
            remediation_id,
            RemediationStatus.VERIFYING,
            outcome,
            verification=result,
            verified=True,
        )
        summary = {name: value for name, value in result.items() if name != "new_critical_or_high"}
        _event(remediation_id, "verified", {"outcome": outcome.value, **summary})
        return {"remediation_id": remediation_id, "status": outcome.value, **result}
    except RemediationStopped as stopped:
        return {"remediation_id": remediation_id, "status": str(stopped), "reason": "not_running"}
    except (SourceError, ApplyError, BuildError) as exc:
        return _fail(remediation_id, str(exc))
    except Exception as exc:  # leave a resting status whatever happens
        logger.exception("Remediation %s failed unexpectedly", remediation_id)
        return _fail(remediation_id, f"unexpected error: {exc}")


@shared_task(
    bind=True, name="src.remediation.worker.execute_approved_remediation", acks_late=True, task_time_limit=3600
)
def execute_approved_remediation(self, remediation_id: int) -> dict:
    return run_remediation(remediation_id)
