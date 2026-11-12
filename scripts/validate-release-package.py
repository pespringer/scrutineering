"""Check the local release evidence and operator package is present."""
from pathlib import Path

required = [
    Path("docs/operations/recovery-go-live-checklist.md"),
    Path("scripts/run-staging-recovery-drill.py"),
    Path("scripts/run-disaster-recovery-drill.py"),
    Path("docs/operations/platform-hardening.md"),
    Path("scripts/validate-migration-matrix.py"),
    Path("monitoring/prometheus-rules.yaml"),
    Path("monitoring/grafana-dashboard.json"),
]
missing = [str(path) for path in required if not path.exists()]
if missing:
    raise SystemExit("missing release package files: " + ", ".join(missing))
print(f"PASS release package ({len(required)} required artifacts)")
