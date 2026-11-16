"""Decide how each finding on an image can be fixed.

Classification runs in the API from finding data alone (the API cannot see
source checkouts): it picks a strategy per finding and groups findings into
actions. The worker later resolves each action against the checked-out source
(which lockfile, which Dockerfile line, which base-image tag).

Strategies:
  dependency_update   npm or pip package with a fixed version: run the package manager.
  os_package_upgrade  distro package (apk, deb, rpm) with a fixed version: upgrade it in the final build stage.
  base_image_bump     runtime binary from the base image (e.g. node itself): move to a newer tag of the same line.
  manual              no fixed version, or an ecosystem we cannot update: shown, never proposed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

OS_FAMILIES = {
    **dict.fromkeys(("alpine", "apk", "wolfi", "chainguard"), "apk"),
    **dict.fromkeys(("debian", "deb", "ubuntu"), "apt"),
    **dict.fromkeys(
        ("rpm", "redhat", "centos", "rocky", "alma", "amazon", "fedora", "oracle", "photon", "suse", "opensuse"), "rpm"
    ),
}
OS_PACKAGE_TYPES = set(OS_FAMILIES)
ECOSYSTEMS = {
    "node-pkg": "npm",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "python-pkg": "pip",
    "pip": "pip",
    "python": "pip",
    "pipenv": "pip",
    "poetry": "pip",
}
BASE_IMAGE_TYPES = {"binary"}


def version_key(version: str) -> tuple:
    """Sort key for package versions: numbers numerically, text lexically ("3.0.19-r0" > "3.0.9-r1")."""
    parts = re.split(r"[.\-+_~]", str(version or ""))
    return tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in parts)


def first_fixed_version(value: str | None) -> str | None:
    """Scanners sometimes list several fixed versions ("4.17.21, 5.0.0"); the lowest is the least disruptive."""
    if not value:
        return None
    candidates = [part.strip() for part in re.split(r"[,\s]+", value) if part.strip()]
    return min(candidates, key=version_key) if candidates else None


@dataclass
class FindingInput:
    id: int
    vuln_key: str
    cve_id: str | None
    package_name: str
    package_version: str | None
    package_type: str | None
    fixed_version: str | None
    severity: str | None = None


@dataclass
class PlannedAction:
    strategy: str
    finding_ids: list[int] = field(default_factory=list)
    vuln_keys: list[str] = field(default_factory=list)
    ecosystem: str | None = None
    package: str | None = None
    from_version: str | None = None
    to_version: str | None = None
    packages: dict[str, str] = field(default_factory=dict)  # os_package_upgrade: package -> minimum fixed version

    @property
    def description(self) -> str:
        if self.strategy == "dependency_update":
            return f"Update {self.package} {self.from_version} → {self.to_version} with {self.ecosystem}"
        if self.strategy == "os_package_upgrade":
            names = ", ".join(sorted(self.packages))
            return f"Upgrade OS package{'s' if len(self.packages) != 1 else ''} {names} in the final build stage"
        return "Rebuild on the newest tag of the same base-image line"

    def as_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "description": self.description,
            "finding_ids": sorted(self.finding_ids),
            "vuln_keys": sorted(set(self.vuln_keys)),
            "ecosystem": self.ecosystem,
            "package": self.package,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "packages": dict(sorted(self.packages.items())),
        }


@dataclass
class ManualFinding:
    finding_id: int
    reason: str


@dataclass
class Plan:
    actions: list[PlannedAction]
    manual: list[ManualFinding]

    @property
    def actionable_finding_ids(self) -> set[int]:
        return {finding_id for action in self.actions for finding_id in action.finding_ids}


def finding_input(finding) -> FindingInput:
    """FindingInput for a `ScanFinding` row."""
    severity = getattr(finding.severity, "value", finding.severity)
    return FindingInput(
        id=finding.id,
        vuln_key=finding.vuln_key,
        cve_id=finding.cve_id,
        package_name=finding.package_name,
        package_version=finding.package_version,
        package_type=finding.package_type,
        fixed_version=finding.fixed_version,
        severity=str(severity) if severity else None,
    )


def classify(finding: FindingInput) -> tuple[str, str | None]:
    """Return (strategy, reason-if-manual) for one finding."""
    fixed = first_fixed_version(finding.fixed_version)
    package_type = (finding.package_type or "").lower()
    if not fixed:
        return "manual", "No fixed version is published yet."
    if package_type in ECOSYSTEMS:
        return "dependency_update", None
    if package_type in OS_PACKAGE_TYPES:
        return "os_package_upgrade", None
    if package_type in BASE_IMAGE_TYPES:
        return "base_image_bump", None
    return "manual", f"Automatic fixes for '{finding.package_type or 'unknown'}' packages are not supported yet."


def plan(findings: list[FindingInput]) -> Plan:
    """Group findings into the smallest set of actions that should fix them."""
    dependency: dict[tuple[str, str], PlannedAction] = {}
    os_upgrades: dict[str, PlannedAction] = {}
    base_bump: PlannedAction | None = None
    manual: list[ManualFinding] = []
    for finding in findings:
        strategy, reason = classify(finding)
        fixed = first_fixed_version(finding.fixed_version)
        if strategy == "manual":
            manual.append(ManualFinding(finding.id, reason or "Not fixable automatically."))
            continue
        if strategy == "dependency_update":
            ecosystem = ECOSYSTEMS[(finding.package_type or "").lower()]
            key = (ecosystem, finding.package_name)
            action = dependency.setdefault(
                key,
                PlannedAction(
                    strategy=strategy,
                    ecosystem=ecosystem,
                    package=finding.package_name,
                    from_version=finding.package_version,
                    to_version=fixed,
                ),
            )
            if version_key(fixed) > version_key(action.to_version or ""):
                action.to_version = fixed
        elif strategy == "os_package_upgrade":
            family = OS_FAMILIES[(finding.package_type or "").lower()]
            action = os_upgrades.setdefault(family, PlannedAction(strategy=strategy, ecosystem=family))
            current = action.packages.get(finding.package_name)
            if current is None or version_key(fixed) > version_key(current):
                action.packages[finding.package_name] = fixed
        else:
            action = base_bump = base_bump or PlannedAction(strategy=strategy)
        action.finding_ids.append(finding.id)
        action.vuln_keys.append(finding.vuln_key)
    actions = [*sorted(dependency.values(), key=lambda a: (a.ecosystem or "", a.package or ""))]
    actions += [os_upgrades[family] for family in sorted(os_upgrades)]
    actions += [base_bump] if base_bump is not None else []
    return Plan(actions=actions, manual=manual)
