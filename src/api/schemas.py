"""Request bodies accepted by the dashboard API."""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field, field_validator

from src.scan.image_identity import parse_image_reference


class ScanRequest(BaseModel):
    image_name: str = Field(min_length=1, max_length=512)
    priority: str = Field(default="normal", pattern="^(low|normal|high)$")

    @field_validator("image_name")
    @classmethod
    def image_name_must_be_an_image_reference(cls, value: str) -> str:
        value = value.strip()
        if not value or any(char.isspace() for char in value):
            raise ValueError("image_name must be a single image reference")
        if value.startswith("fs:"):
            # Filesystem scans are an internal remediation tool, not a public scan target.
            raise ValueError("image_name must be a container image reference")
        parse_image_reference(value)
        return value


class BulkIdsRequest(BaseModel):
    ids: list[int | str] = Field(min_length=1, max_length=100)


class RegistryTagItem(BaseModel):
    repository: str = Field(min_length=1, max_length=255)
    tag: str = Field(min_length=1, max_length=128)
    # The image the operator saw. The server resolves the tag itself and refuses if it has moved.
    digest: str = Field(pattern="^sha256:[a-f0-9]{64}$")


class RegistryDeleteRequest(BaseModel):
    items: list[RegistryTagItem] = Field(min_length=1, max_length=100)


class BulkFindingAssignmentRequest(BaseModel):
    finding_ids: list[int] = Field(min_length=1, max_length=100)
    assignee: str | None = Field(default=None, max_length=128)

    @field_validator("assignee")
    @classmethod
    def assignee_is_safe(cls, value: str | None) -> str | None:
        if value is not None and any(char.isspace() for char in value.strip()):
            raise ValueError("assignee must not contain whitespace")
        return value.strip() if value else None


class RemediationRequest(BaseModel):
    image_id: int = Field(gt=0)
    finding_ids: list[int] = Field(min_length=1, max_length=50)


class ImageSourceRequest(BaseModel):
    """Where an image is built from. Paths are relative to the repository root."""

    repository: str = Field(min_length=1, max_length=1024)
    ref: str = Field(default="HEAD", max_length=256)
    dockerfile_path: str = Field(default="Dockerfile", max_length=512)
    build_context: str = Field(default=".", max_length=512)
    build_args: dict[str, str] = Field(default_factory=dict)
    test_command: list[str] | None = None


class ComplianceExportRequest(BaseModel):
    """A date range, as whole UTC days: `since` is included, `until` is the last day included."""

    since: date
    until: date

    @field_validator("until")
    @classmethod
    def range_is_sane(cls, value: date, info) -> date:
        since = info.data.get("since")
        if since is not None and value < since:
            raise ValueError("until must not be before since")
        if since is not None and (value - since).days + 1 > 366:
            raise ValueError("the range is at most 366 days")
        return value
