"""Tests for scan provenance envelopes."""

import pytest

from src.scan.provenance import ScannerProvenance, provenance_maps


def test_provenance_maps_are_sorted_and_separate_database_versions():
    records = [
        ScannerProvenance("grype", "0.80.0", "2026-11-07"),
        ScannerProvenance("trivy", "0.60.0"),
    ]

    assert provenance_maps(records) == (
        {"grype": "0.80.0", "trivy": "0.60.0"},
        {"grype": "2026-11-07"},
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scanner": "", "scanner_version": "1"},
        {"scanner": "trivy", "scanner_version": ""},
    ],
)
def test_provenance_requires_tool_identity(kwargs):
    with pytest.raises(ValueError):
        ScannerProvenance(**kwargs)
