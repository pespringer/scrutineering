#!/usr/bin/env python3
"""Trim Trivy or Grype JSON to the fields the scanner parsers read, or a CycloneDX SBOM to its components.

Usage: trim-scanner-output.py {trivy|grype|cyclonedx} RAW_JSON > TRIMMED_JSON

Keeps recorded fixtures small and deterministic (no timestamps, no database
metadata). Output is sorted so re-recording produces a readable diff.
"""

import json
import sys

TRIVY_VULN_FIELDS = (
    "VulnerabilityID",
    "PkgName",
    "PkgPath",
    "InstalledVersion",
    "FixedVersion",
    "Severity",
    "Title",
    "CVSS",
)
# Grype has no title field: the parser titles findings from the description, so keep it.
GRYPE_VULN_FIELDS = ("id", "severity", "description", "fix")
GRYPE_ARTIFACT_FIELDS = ("name", "version", "type", "locations", "purl")


def trim_trivy(data: dict) -> dict:
    results = []
    for result in data.get("Results") or []:
        vulns = [
            {key: vuln[key] for key in TRIVY_VULN_FIELDS if key in vuln} for vuln in result.get("Vulnerabilities") or []
        ]
        vulns.sort(key=lambda v: (v.get("PkgName", ""), v.get("VulnerabilityID", "")))
        results.append(
            {key: result[key] for key in ("Target", "Class", "Type") if key in result} | {"Vulnerabilities": vulns}
        )
    return {"SchemaVersion": data.get("SchemaVersion", 2), "ArtifactName": data.get("ArtifactName"), "Results": results}


def trim_grype(data: dict) -> dict:
    matches = []
    for match in data.get("matches") or []:
        vuln, artifact = match.get("vulnerability", {}), match.get("artifact", {})
        matches.append(
            {
                "vulnerability": {key: vuln[key] for key in GRYPE_VULN_FIELDS if key in vuln},
                "artifact": {key: artifact[key] for key in GRYPE_ARTIFACT_FIELDS if key in artifact},
            }
        )
    matches.sort(key=lambda m: (m["artifact"].get("name", ""), m["vulnerability"].get("id", "")))
    return {"matches": matches}


CYCLONEDX_COMPONENT_FIELDS = ("bom-ref", "type", "name", "version", "purl", "group")


def trim_cyclonedx(data: dict) -> dict:
    """The SBOM without its embedded vulnerabilities, timestamps or serial number."""
    components = [
        {key: item[key] for key in CYCLONEDX_COMPONENT_FIELDS if key in item} for item in data.get("components") or []
    ]
    components.sort(key=lambda item: (item.get("type", ""), item.get("name", ""), item.get("version", "")))
    return {
        "bomFormat": data["bomFormat"],
        "specVersion": data["specVersion"],
        "version": data.get("version", 1),
        "components": components,
    }


def main() -> None:
    kind, path = sys.argv[1], sys.argv[2]
    data = json.load(open(path))
    trimmed = {"trivy": trim_trivy, "grype": trim_grype, "cyclonedx": trim_cyclonedx}[kind](data)
    json.dump(trimmed, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
