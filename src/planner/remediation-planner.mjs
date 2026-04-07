const severityRank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const classRuleTable = {
  outdated_dependency: {
    actionType: "version_bump",
    fallbackAction: "manual_review",
    rationale: "Upgrade the vulnerable package to the nearest safe version.",
  },
  vulnerable_transitive_dependency: {
    actionType: "package_pin_update",
    fallbackAction: "manual_review",
    rationale: "Pin a safe transitive dependency override in the manifest.",
  },
  unpinned_dependency: {
    actionType: "package_pin_update",
    fallbackAction: "manual_review",
    rationale: "Pin package versions to remove floating-risk resolution.",
  },
  os_package_vulnerability: {
    actionType: "package_pin_update",
    fallbackAction: "base_image_swap",
    rationale: "Upgrade the vulnerable operating-system package to a fixed version.",
  },
  vulnerable_base_image: {
    actionType: "base_image_swap",
    fallbackAction: "manual_review",
    rationale: "Move to a patched base image digest or tag.",
  },
  unpinned_base_image_tag: {
    actionType: "base_image_swap",
    fallbackAction: "manual_review",
    rationale: "Pin the base image to an immutable digest.",
  },
  vulnerable_lockfile_resolution: {
    actionType: "package_pin_update",
    fallbackAction: "manual_review",
    rationale: "Refresh lockfile resolution to a fixed dependency set.",
  },
  insecure_default_package: {
    actionType: "version_bump",
    fallbackAction: "manual_review",
    rationale: "Replace insecure default package release with safe version.",
  },
  stale_digest_reference: {
    actionType: "base_image_swap",
    fallbackAction: "manual_review",
    rationale: "Replace stale digest with a trusted patched digest.",
  },
};

function normalizeSeverity(severity) {
  const key = String(severity || "").toLowerCase();
  return severityRank[key] ? key : "medium";
}

function stableStringCompare(a, b) {
  return String(a).localeCompare(String(b), "en");
}

function compareFindings(a, b) {
  return (
    stableStringCompare(a.id, b.id) ||
    stableStringCompare(a.packageName, b.packageName) ||
    stableStringCompare(a.currentVersion, b.currentVersion)
  );
}

function targetKey(finding, proposal) {
  const filePath = finding.filePath || "<unknown>";
  if (proposal.actionType === "base_image_swap") {
    return `${filePath}:base_image`;
  }

  return `${filePath}:pkg:${finding.packageName}`;
}

function buildEvidence(finding) {
  return {
    findingId: finding.id,
    advisoryId: finding.advisoryId,
    vulnerabilityClass: finding.vulnerabilityClass,
    severity: normalizeSeverity(finding.severity),
    packageName: finding.packageName,
    currentVersion: finding.currentVersion,
    fixedVersion: finding.fixedVersion,
    filePath: finding.filePath,
  };
}

function buildChange(proposal, finding, dryRun) {
  const patchType = proposal.actionType === "base_image_swap" ? "dockerfile" : "manifest";

  return {
    target: {
      filePath: finding.filePath,
      packageName: finding.packageName,
    },
    action: proposal.actionType,
    from: finding.currentVersion,
    to: finding.fixedVersion,
    patchType,
    mode: dryRun ? "dry_run" : "apply",
    explainability: {
      selectedAction: proposal.actionType,
      fallbackAction: proposal.fallbackAction,
      rationale: proposal.rationale,
      evidence: buildEvidence(finding),
    },
  };
}

function pickConflictWinner(current, challenger) {
  const currentRank = severityRank[current.severity];
  const challengerRank = severityRank[challenger.severity];
  if (challengerRank > currentRank) {
    return challenger;
  }
  if (challengerRank < currentRank) {
    return current;
  }

  if (stableStringCompare(challenger.finding.fixedVersion, current.finding.fixedVersion) > 0) {
    return challenger;
  }

  if (stableStringCompare(challenger.finding.fixedVersion, current.finding.fixedVersion) < 0) {
    return current;
  }

  return compareFindings(challenger.finding, current.finding) < 0 ? challenger : current;
}

function normalizeFinding(raw) {
  return {
    id: raw.id,
    vulnerabilityClass: raw.vulnerabilityClass,
    severity: normalizeSeverity(raw.severity),
    packageName: raw.packageName,
    currentVersion: raw.currentVersion,
    fixedVersion: raw.fixedVersion,
    filePath: raw.filePath,
    advisoryId: raw.advisoryId,
  };
}

export function createRemediationPlan(input, options = {}) {
  const findings = Array.isArray(input?.findings) ? input.findings : [];
  const dryRun = Boolean(options.dryRun);

  const normalizedFindings = findings.map(normalizeFinding).sort(compareFindings);

  const supportedFindings = [];
  const unsupportedFindings = [];
  const conflictDetails = [];

  const selectedByTarget = new Map();

  for (const finding of normalizedFindings) {
    const rule = classRuleTable[finding.vulnerabilityClass];
    if (!rule) {
      unsupportedFindings.push({
        findingId: finding.id,
        vulnerabilityClass: finding.vulnerabilityClass,
        reason: "unsupported_vulnerability_class",
      });
      continue;
    }

    const proposal = {
      ...rule,
      finding,
      severity: finding.severity,
    };

    const key = targetKey(finding, proposal);
    const existing = selectedByTarget.get(key);

    if (!existing) {
      selectedByTarget.set(key, proposal);
      supportedFindings.push(finding.id);
      continue;
    }

    if (
      existing.actionType === proposal.actionType &&
      existing.finding.fixedVersion === proposal.finding.fixedVersion
    ) {
      supportedFindings.push(finding.id);
      continue;
    }

    const winner = pickConflictWinner(existing, proposal);
    const loser = winner === existing ? proposal : existing;
    selectedByTarget.set(key, winner);
    supportedFindings.push(finding.id);

    conflictDetails.push({
      target: key,
      resolution: "selected_highest_priority_fix",
      winnerFindingId: winner.finding.id,
      loserFindingId: loser.finding.id,
      winnerAction: winner.actionType,
      loserAction: loser.actionType,
    });
  }

  const changes = Array.from(selectedByTarget.values())
    .map((proposal) => buildChange(proposal, proposal.finding, dryRun))
    .sort((a, b) => {
      return (
        stableStringCompare(a.target.filePath, b.target.filePath) ||
        stableStringCompare(a.target.packageName, b.target.packageName) ||
        stableStringCompare(a.to, b.to)
      );
    });

  const total = normalizedFindings.length;
  const coverage = total === 0 ? 1 : supportedFindings.length / total;

  return {
    planVersion: "1.0.0",
    dryRun,
    summary: {
      totalFindings: total,
      supportedFindings: supportedFindings.length,
      unsupportedFindings: unsupportedFindings.length,
      coverage,
      conflicts: conflictDetails.length,
      deterministicOrdering: true,
    },
    changes,
    conflicts: conflictDetails,
    unsupportedFindings,
    writeActions: dryRun ? [] : changes,
  };
}

export function getSupportedVulnerabilityClasses() {
  return Object.keys(classRuleTable).sort(stableStringCompare);
}
