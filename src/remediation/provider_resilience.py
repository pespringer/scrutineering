"""Provider response and retry guards shared by publication/recovery adapters."""

from __future__ import annotations

from dataclasses import dataclass

from src.platform.controls import parse_retry_after


@dataclass(frozen=True)
class ProviderResponse:
    status: int
    body: dict
    schema_version: str = "v1"
    retry_after: int = 0

    def validate(self) -> "ProviderResponse":
        if not 100 <= self.status <= 599:
            raise ValueError("invalid provider status")
        if self.schema_version != "v1":
            raise ValueError("unsupported provider response schema")
        if not isinstance(self.body, dict):
            raise ValueError("provider response body must be an object")
        return self


def bounded_provider_page(items: list[dict], cursor: str | None, *, maximum: int = 100) -> tuple[list[dict], str | None]:
    if len(items) > maximum:
        raise ValueError("provider page exceeds maximum")
    if cursor is not None and (not cursor or len(cursor) > 256):
        raise ValueError("invalid provider cursor")
    return items, cursor


def response_from_headers(status: int, body: dict, headers: dict[str, str]) -> ProviderResponse:
    return ProviderResponse(status=status, body=body, retry_after=parse_retry_after(headers.get("retry-after"))).validate()
