"""Publish a verified remediation as a GitHub pull request (decision D4: GitHub is the only provider).

    ready ──operator: publish──▶ published ──PR merged, image rebuilt and rescanned──▶ completed
                                          └──PR closed unmerged, or the rebuilt image still has a target──▶ failed

Publishing pushes the verified patch, as one commit on top of the commit it was made
against, to `scrutineering/remediation-<id>` and opens a pull request whose body holds the
plan and the before/after scan comparison. It never merges. Publishing only happens when an
operator asks for it, so setting `GITHUB_TOKEN` (also used to pull from ghcr.io) never opens
pull requests by itself.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from celery import shared_task

from src.db.connection import get_session
from src.db.models import Remediation, RemediationPublication, RemediationStatus, ScanFinding
from src.db.repositories import RemediationRepository
from src.remediation.build import BuildError, askpass_env, git
from src.remediation.sources import clone_url, github_repository
from src.scan.image_identity import parse_image_reference

logger = logging.getLogger(__name__)

PROVIDER = "github"
GITHUB_API = "https://api.github.com"
MAX_PATCH_BYTES = 200_000  # the worker stores at most this much of a patch; a longer one was truncated
MAX_BODY_CHARS = 60_000
COMMIT_AUTHOR = ("Scrutineering", "scrutineering@users.noreply.github.com")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class PublishError(RuntimeError):
    """The remediation could not be published. The message is safe to show (it never holds the token)."""


class PublishStopped(Exception):
    """The remediation is no longer `ready`."""


def token() -> str:
    return os.environ.get("GITHUB_TOKEN", "")


def branch_for(remediation_id: int) -> str:
    return f"scrutineering/remediation-{remediation_id}"


class GitHub:
    """The few GitHub REST calls publication needs. Errors never include the token."""

    def __init__(self, access_token: str, transport=urlopen):
        if not access_token:
            raise PublishError("GITHUB_TOKEN is not set")
        self._token = access_token
        self._transport = transport

    def request(self, method: str, path: str, payload: dict | None = None):
        request = Request(
            f"{GITHUB_API}{path}",
            data=json.dumps(payload).encode() if payload is not None else None,
            method=method,
            headers={
                "accept": "application/vnd.github+json",
                "authorization": f"Bearer {self._token}",
                "x-github-api-version": "2022-11-28",
                "content-type": "application/json",
                "user-agent": "scrutineering",
            },
        )
        try:
            with self._transport(request, timeout=20) as response:
                return json.loads(response.read().decode() or "null")
        except HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode())
            except (ValueError, OSError):
                detail = {}
            raise GitHubError(exc.code, detail) from None
        except URLError as exc:
            raise PublishError(f"GitHub is unreachable: {exc.reason}") from None

    def default_branch(self, repository: str) -> str:
        return str(self.request("GET", f"/repos/{repository}")["default_branch"])

    def open_pull_request(self, repository: str, *, head: str, base: str, title: str, body: str) -> dict:
        """Open the pull request, or return the open one that already exists for `head`."""
        try:
            return self.request(
                "POST", f"/repos/{repository}/pulls", {"title": title, "head": head, "base": base, "body": body}
            )
        except GitHubError as exc:
            if exc.status != 422 or "already exists" not in exc.message:
                raise
        owner = repository.split("/", 1)[0]
        existing = self.request("GET", f"/repos/{repository}/pulls?state=open&head={quote(f'{owner}:{head}')}")
        if not existing:
            raise PublishError(f"GitHub says a pull request for {head} exists but none is open")
        return existing[0]


class GitHubError(PublishError):
    def __init__(self, status: int, detail: dict):
        errors = "; ".join(str(item.get("message") or item) for item in detail.get("errors") or [])
        self.status = status
        self.message = f"{detail.get('message') or 'request failed'}{': ' + errors if errors else ''}"
        super().__init__(f"GitHub returned {status}: {self.message}"[:1000])


@dataclass
class Job:
    remediation_id: int
    repository: str
    base: str | None
    commit: str
    patch: str
    title: str
    body: str
    image_digest: str | None
    commit_date: str
    previous_head: str | None


def _finding_rows(findings: list[ScanFinding]) -> list[str]:
    rows = ["| Vulnerability | Package | Installed | Fixed in | Severity |", "|---|---|---|---|---|"]
    for finding in sorted(findings, key=lambda item: (item.cve_id or "", item.package_name)):
        severity = finding.severity.value if finding.severity else "unknown"
        rows.append(
            f"| {finding.cve_id or 'n/a'} | {finding.package_name} | {finding.package_version or ''} "
            f"| {finding.fixed_version or ''} | {severity} |"
        )
    return rows


def pull_request_title(remediation_id: int, count: int, repository: str) -> str:
    noun = "vulnerability" if count == 1 else "vulnerabilities"
    return f"Fix {count} {noun} in {repository} (Scrutineering #{remediation_id})"


def pull_request_body(remediation: Remediation, open_findings: int) -> str:
    """The plan and the before/after comparison, from what the server built and scanned."""
    image = remediation.image
    verification = remediation.verification or {}
    new_blocking = verification.get("new_critical_or_high") or []
    lines = [
        f"Scrutineering remediation #{remediation.id} for `{image.full_name}`"
        + (f" (`{image.digest}`)" if image.digest else "")
        + ".",
        "",
        f"## Findings fixed ({len(remediation.findings)})",
        "",
        *_finding_rows(list(remediation.findings)),
        "",
        "## Changes",
        "",
        *[
            f"- {(action.detail or {}).get('description') or action.action_type.value}"
            for action in remediation.actions
        ],
        "",
        "## Verification",
        "",
        f"Scrutineering built this branch as `{remediation.candidate_image}` (`{remediation.candidate_digest}`) "
        "and scanned it with the same scanners and settings as the image.",
        "",
        "| | Image now | Patched candidate |",
        "|---|---|---|",
        f"| Open findings | {open_findings} | {verification.get('candidate_findings', 'n/a')} |",
        f"| Targeted findings | {verification.get('targeted', len(remediation.findings))} "
        f"| {len(verification.get('still_present') or [])} |",
        f"| New critical or high | | {len(new_blocking)} |",
    ]
    if new_blocking:
        lines += ["", "New critical or high findings, accepted by a security operator:", ""]
        lines += [f"- {item.get('cve_id')} in {item['package_name']} ({item.get('severity')})" for item in new_blocking]
    lines += [
        "",
        "Merging does not change the running image. Once the image is rebuilt from this change, the next "
        "scan of it marks the remediation completed if none of the findings above remain.",
    ]
    body = "\n".join(lines)
    return body if len(body) <= MAX_BODY_CHARS else body[:MAX_BODY_CHARS] + "\n\n(truncated)"


def _load(remediation_id: int) -> Job:
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise PublishStopped("deleted")
        if remediation.status != RemediationStatus.READY:
            raise PublishStopped(remediation.status.value)
        image = remediation.image
        repository = github_repository(image.source.repository if image.source else None)
        if repository is None:
            raise PublishError("the image's source is not an https://github.com repository")
        if not remediation.patch or not remediation.source_commit or not _COMMIT.fullmatch(remediation.source_commit):
            raise PublishError("the remediation has no verified patch to publish")
        if len(remediation.patch) >= MAX_PATCH_BYTES:
            raise PublishError("the patch is too large to have been stored whole; apply it by hand")
        open_findings = (
            session.query(ScanFinding)
            .filter(ScanFinding.image_id == image.id, ScanFinding.resolved_at.is_(None))
            .count()
        )
        previous = _publication(session, remediation_id)
        ref = image.source.ref
        stamp = remediation.approved_at or remediation.created_at or datetime(2000, 1, 1)
        return Job(
            remediation_id=remediation_id,
            repository=repository,
            base=None if ref == "HEAD" or _COMMIT.fullmatch(ref) else ref,
            commit=remediation.source_commit,
            patch=remediation.patch,
            title=pull_request_title(
                remediation_id, len(remediation.findings), parse_image_reference(image.full_name).repository
            ),
            body=pull_request_body(remediation, open_findings),
            image_digest=image.digest,
            # A fixed date makes the commit reproducible, so a retried push of the same patch is a no-op.
            commit_date=stamp.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000"),
            previous_head=previous.head_commit if previous else None,
        )


def _publication(session, remediation_id: int) -> RemediationPublication | None:
    return (
        session.query(RemediationPublication)
        .filter_by(remediation_id=remediation_id, provider=PROVIDER)
        .order_by(RemediationPublication.id.desc())
        .first()
    )


def push_branch(job: Job, workdir: Path, access_token: str) -> str:
    """Commit the patch on top of `job.commit` and push it to the remediation branch. Returns the new commit."""
    remote = clone_url(f"https://github.com/{job.repository}")
    root = workdir / "source"
    auth = askpass_env(workdir, access_token)
    git(["clone", "--quiet", "--no-checkout", "--", remote, str(root)], env=auth)
    git(["checkout", "--quiet", "--detach", job.commit], cwd=root)
    patch = workdir / "remediation.patch"
    patch.write_text(job.patch if job.patch.endswith("\n") else job.patch + "\n")
    git(["apply", "--index", "--whitespace=nowarn", str(patch)], cwd=root)
    name, email = COMMIT_AUTHOR
    identity = {
        "GIT_AUTHOR_NAME": name,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": name,
        "GIT_COMMITTER_EMAIL": email,
        "GIT_AUTHOR_DATE": job.commit_date,
        "GIT_COMMITTER_DATE": job.commit_date,
    }
    git(["commit", "--quiet", "--no-verify", "-m", job.title], cwd=root, env=identity)
    head = git(["rev-parse", "HEAD"], cwd=root)
    branch = branch_for(job.remediation_id)
    # Overwrite the branch only if it still holds what we pushed last time; never someone else's commits.
    lease = f"--force-with-lease=refs/heads/{branch}:{job.previous_head or ''}"
    try:
        git(["push", "--quiet", lease, "origin", f"HEAD:refs/heads/{branch}"], cwd=root, env=auth)
    except BuildError as exc:
        if "stale info" in str(exc) or "rejected" in str(exc):
            raise PublishError(f"{branch} already exists on GitHub with other commits; delete it to publish") from exc
        message = str(exc).replace(access_token, "***") if access_token else str(exc)
        raise PublishError(message) from exc
    return head


def _record(remediation_id: int, job: Job | None, **values) -> RemediationPublication:
    with get_session() as session:
        publication = _publication(session, remediation_id)
        if publication is None:
            publication = RemediationPublication(
                remediation_id=remediation_id,
                provider=PROVIDER,
                repository=job.repository if job else "",
                idempotency_key=f"remediation-{remediation_id}",
                request_hash=hashlib.sha256((job.patch if job else "").encode()).hexdigest(),
                branch=branch_for(remediation_id),
            )
            session.add(publication)
        for name, value in values.items():
            setattr(publication, name, value)
        session.flush()
        session.expunge(publication)
        return publication


def publish(remediation_id: int, *, github: GitHub | None = None) -> dict:
    """Push the verified patch and open the pull request. A failure leaves the remediation `ready`."""
    job = None
    try:
        job = _load(remediation_id)
        client = github or GitHub(token())
        base = job.base or client.default_branch(job.repository)
        with tempfile.TemporaryDirectory(prefix="scrutineering-publish-") as workdir:
            head = push_branch(job, Path(workdir), token())
        pull = client.open_pull_request(
            job.repository, head=branch_for(remediation_id), base=base, title=job.title, body=job.body
        )
    except PublishStopped as stopped:
        return {"remediation_id": remediation_id, "status": str(stopped), "reason": "not_ready"}
    except (PublishError, BuildError) as exc:
        reason = str(exc)[:2000]
        _record(remediation_id, job, status="failed", error_message=reason)
        with get_session() as session:
            RemediationRepository.record_event(session, remediation_id, "publication_failed", {"reason": reason[:500]})
        return {"remediation_id": remediation_id, "status": "ready", "publication": "failed", "reason": reason}
    _record(
        remediation_id,
        job,
        repository=job.repository,
        status="open",
        url=str(pull["html_url"]),
        provider_number=int(pull["number"]),
        base_branch=base,
        head_commit=head,
        image_digest=job.image_digest,
        error_message=None,
        completed_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        detail = {"url": pull["html_url"], "number": pull["number"], "branch": branch_for(remediation_id)}
        if remediation is not None and remediation.status == RemediationStatus.READY:
            RemediationRepository.update_status(session, remediation_id, RemediationStatus.PUBLISHED)
        RemediationRepository.record_event(session, remediation_id, "published", detail)
    return {"remediation_id": remediation_id, "status": RemediationStatus.PUBLISHED.value, **detail}


@shared_task(bind=True, name="src.remediation.publish.publish_remediation", acks_late=True, task_time_limit=900)
def publish_remediation(self, remediation_id: int) -> dict:
    try:
        return publish(remediation_id)
    except Exception as exc:  # record the failure; the remediation stays `ready` so it can be published again
        logger.exception("Publishing remediation %s failed unexpectedly", remediation_id)
        _record(remediation_id, None, status="failed", error_message=f"unexpected error: {exc}"[:2000])
        return {"remediation_id": remediation_id, "status": "ready", "publication": "failed"}
