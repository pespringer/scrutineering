"""Deleting tags from the bundled registry, and the reasons not to (docs/design/registry-management.md).

Only ever by tag: deleting by digest removes every tag that shares the image. That needs `registry:3`.
A tag something still needs is refused, and there is no override. The caller owns the transaction:
`delete_tag` locks the rows it decides on, so nothing can start needing the tag before it commits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from src.config import get_settings
from src.db.models import Deployment, Image, Remediation, Scan, ScanStatus
from src.remediation.state_machine import TERMINAL
from src.scan.deployments import RETENTION, utcnow
from src.scan.image_identity import ImageIdentity, parse_image_reference
from src.scan.registry_catalog import RegistryClient, RegistryError, image_summary, valid_repository, valid_tag
from src.scan.runtime_discovery import running_since

CANDIDATE_TAG = re.compile(r"scrutineering-candidate-(\d{1,18})")


class Refused(Exception):
    """The tag wasn't deleted. `code` is stable; `reason` is shown to the operator."""

    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class Tag:
    repository: str
    tag: str

    @property
    def name(self) -> str:
        """As the services, and so the records, name it."""
        return f"{get_settings().local_registry_host.strip()}/{self.repository}:{self.tag}"

    @property
    def repo_names(self) -> set[str]:
        """The repository under both names: the services' and the one Docker on the host uses."""
        settings = get_settings()
        hosts = {settings.local_registry_host.strip(), settings.local_registry_public_host.strip()}
        return {f"{host}/{self.repository}" for host in hosts if host}


def _identity(reference: str) -> ImageIdentity | None:
    try:
        return parse_image_reference(reference)
    except ValueError:
        return None


def _locked_images(session: Session, tag: Tag) -> list:
    """The tag's tracked images. Locking them also blocks new scans and remediations, whose rows refer to them."""
    return (
        session.query(Image.id, Image.last_seen_running_at)
        .filter(Image.repo_name.in_(tag.repo_names), Image.tag == tag.tag)
        .order_by(Image.id)
        .with_for_update()
        .all()
    )


def _check_remediations(session: Session, tag: Tag, image_ids: list[int]) -> None:
    number = CANDIDATE_TAG.fullmatch(tag.tag)
    wanted = Remediation.image_id.in_(image_ids) | (Remediation.candidate_image == tag.name)
    if number:
        wanted |= Remediation.id == int(number.group(1))
    columns = (Remediation.id, Remediation.image_id, Remediation.status, Remediation.candidate_image)
    for row in session.query(*columns).filter(wanted).order_by(Remediation.id).with_for_update():
        if row.status in TERMINAL:
            continue
        if row.image_id not in image_ids and row.candidate_image != tag.name:
            # Its number matches, but it may belong to another repository, or build this tag next.
            image = session.get(Image, row.image_id)
            if image is None or parse_image_reference(image.full_name).repository != tag.repository:
                continue
        raise Refused("remediation_active", f"Remediation {row.id} still needs it. Finish or cancel it first.")


def _check_scans(session: Session, image_ids: list[int]) -> None:
    active = (ScanStatus.PENDING.value, ScanStatus.RUNNING.value)
    if session.query(Scan.id).filter(Scan.image_id.in_(image_ids), Scan.status.in_(active)).first():
        raise Refused("scan_active", "A scan of it is pending or running.")


def _other_tag_has(client: RegistryClient, tag: Tag, digest: str) -> bool:
    for other in client.tags(tag.repository):
        try:
            if other != tag.tag and client.digest(tag.repository, other) == digest:
                return True
        except RegistryError as error:
            if error.status != 404:
                raise
    return False


def _check_running(session: Session, client: RegistryClient, tag: Tag, digest: str, images: list, now: datetime):
    # Discovery that has been off for this long can't say a container still runs.
    listed = session.query(Deployment.name, Deployment.image_ref, Deployment.running_digests).filter(
        Deployment.gone_at.is_(None), Deployment.last_seen_at >= now - RETENTION
    )
    ours = []
    for row in listed:
        identity = _identity(row.image_ref)
        if identity is None or identity.repo_name not in tag.repo_names:
            continue
        if identity.digest is None and identity.tag == tag.tag:
            raise Refused("running", f"Container {row.name} runs it. Stop the container first.")
        ours.append(row)
    if ours:
        digests = {digest, *image_summary(client, tag.repository, digest).blobs}
        for row in ours:
            if digests & set(row.running_digests or []) and not _other_tag_has(client, tag, digest):
                raise Refused("running", f"Container {row.name} runs this image, and no other tag keeps it.")
    # Without container records (containerd), all discovery says is when it last saw the image run.
    recorded = {
        image_id
        for (image_id,) in session.query(Deployment.image_id).filter(
            Deployment.image_id.in_([image.id for image in images])
        )
    }
    for image in images:
        seen = image.last_seen_running_at
        if image.id not in recorded and seen is not None and seen >= running_since(now):
            raise Refused("running", "Runtime discovery saw it running in the last 30 minutes.")


def _registry_refusal(error: RegistryError) -> Refused:
    if error.status == 404:
        return Refused("tag_not_found", "It's no longer in the registry.")
    return Refused("registry_failed", f"The registry didn't delete it: {error}.")


_DELETE_REFUSALS = {
    400: ("registry_delete_unsupported", "This registry can't delete single tags. It needs registry:3."),
    405: ("registry_delete_disabled", "Deletion is turned off in the registry."),
}


def delete_tag(session: Session, client: RegistryClient, tag: Tag, expected_digest: str) -> list[int]:
    """Delete one tag unless something needs it, and archive its tracked images. Returns their IDs.

    `expected_digest` is a precondition, never a fact: the tag is resolved here, and refused if it moved.
    """
    if not valid_repository(tag.repository) or not valid_tag(tag.tag):
        raise Refused("invalid_image_reference", "That isn't a valid repository and tag.")
    images = _locked_images(session, tag)
    image_ids = [image.id for image in images]
    _check_remediations(session, tag, image_ids)
    _check_scans(session, image_ids)
    try:
        digest = client.digest(tag.repository, tag.tag)
        if digest != expected_digest:
            raise Refused("tag_changed", "It was pushed again since the list was loaded. Refresh and check it.")
        _check_running(session, client, tag, digest, images, utcnow())
    except RegistryError as error:
        raise _registry_refusal(error) from error
    try:
        client.delete_tag(tag.repository, tag.tag)
    except RegistryError as error:
        known = _DELETE_REFUSALS.get(error.status)
        raise (Refused(*known) if known else _registry_refusal(error)) from error
    session.query(Image).filter(Image.id.in_(image_ids)).update({Image.active: False}, synchronize_session=False)
    return image_ids
