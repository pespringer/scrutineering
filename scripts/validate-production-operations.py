#!/usr/bin/env python3
"""Validate the receiver-independent 201-300 production slice contract."""

from src.platform.production_operations import receiver_independent_slice_manifest, telemetry_dashboard_catalog


def main() -> None:
    manifest = receiver_independent_slice_manifest()
    assert len(manifest) == 100
    assert [item["slice"] for item in manifest] == list(range(201, 301))
    assert not any(item["receiver_required"] for item in manifest)
    assert len(telemetry_dashboard_catalog()) >= 10
    print("production operations contract: 100 receiver-independent slices, 10 telemetry panels")


if __name__ == "__main__":
    main()

