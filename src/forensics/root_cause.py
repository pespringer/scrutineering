"""Root cause analysis for container incidents.

Re-exports RootCauseAnalyzer from timeline module for a clean public API.

Usage:
    from src.forensics.root_cause import RootCauseAnalyzer, RootCauseHypothesis
    rca = RootCauseAnalyzer()
    hypotheses = rca.analyze(container_id, anomalies, findings)
"""

from src.forensics.timeline import RootCauseAnalyzer, RootCauseHypothesis

__all__ = ["RootCauseAnalyzer", "RootCauseHypothesis"]
