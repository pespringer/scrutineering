"""Request bodies accepted by the dashboard API."""

from __future__ import annotations


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
