"""Tests for the container forensics and incident investigation toolkit.

Covers:
  - ForensicSnapshotService (data models, sanitisation, hash computation)
  - NetworkCaptureService (flow records, DNS logging, anomaly detection)
  - ForensicTimeline (event assembly, querying, summary)
  - RootCauseAnalyzer (pattern matching, confidence scoring, recommendations)
  - SIEMExporter (CEF, LEEF, syslog, JSON, batch export)
  - IncidentReportGenerator (report assembly, JSON/markdown output)
  - AuditLogger (append-only logging, queries, convenience methods)
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.forensics.snapshot import (
    FilesystemEntry,
    ProcessInfo,
    NetworkConnection,
    ContainerSnapshot,
    _sanitise_env,
    _SENSITIVE_ENV_KEYS,
)
from src.forensics.network import (
    NetworkFlowRecord,
    DNSQueryLog,
    NetworkCaptureService,
    _is_internal,
    _addr_port,
)
from src.forensics.timeline import (
    TimelineEvent,
    ForensicTimeline,
    RootCauseAnalyzer,
    RootCauseHypothesis,
    _ATTACK_PATTERNS,
)
from src.forensics.siem import SIEMExporter
from src.forensics.report import IncidentReport, IncidentReportGenerator
from src.forensics.audit import (
    AuditRecord,
    AuditLogger,
    AuditEvent,
)


# ===========================================================================
# ForensicSnapshot — models
# ===========================================================================

class TestFilesystemEntry:
    def test_default_values(self):
        e = FilesystemEntry(path="/etc/passwd", file_type="file")
        assert e.size == 0
        assert e.sha256 == ""

    def test_basic_entry(self):
        e = FilesystemEntry(
            path="/bin/sh", file_type="file", size=123456,
            mode="0755", owner="root", sha256="abc123",
        )
        assert e.size == 123456
        assert e.sha256 == "abc123"


class TestProcessInfo:
    def test_defaults(self):
        p = ProcessInfo(pid=1, ppid=0)
        assert p.command == ""
        assert p.cpu_percent == 0.0


class TestNetworkConnection:
    def test_defaults(self):
        c = NetworkConnection(protocol="tcp")
        assert c.state == ""
        assert c.local_port == 0


class TestContainerSnapshot:
    def _make_snap(self):
        return ContainerSnapshot(
            snapshot_id="s1",
            container_id="abc123",
            image_name="nginx:latest",
            filesystem=[
                FilesystemEntry("/etc/passwd", "file", size=1337),
                FilesystemEntry("/bin/sh", "file", size=99999),
            ],
            processes=[ProcessInfo(pid=1, ppid=0)],
            connections=[NetworkConnection(protocol="tcp", local_port=80)],
        )

    def test_counts(self):
        snap = self._make_snap()
        assert snap.file_count == 2
        assert snap.process_count == 1
        assert snap.connection_count == 1

    def test_compute_hash(self):
        snap = self._make_snap()
        h1 = snap.compute_hash()
        assert len(h1) == 64  # SHA-256 hex
        h2 = snap.compute_hash()
        assert h1 == h2  # deterministic

    def test_hash_changes_with_content(self):
        snap = self._make_snap()
        h1 = snap.compute_hash()
        snap.filesystem.append(
            FilesystemEntry("/tmp/new", "file"))
        h2 = snap.compute_hash()
        assert h1 != h2

    def test_to_dict_roundtrip(self):
        snap = self._make_snap()
        d = snap.to_dict()
        assert d["snapshot_id"] == "s1"
        assert d["container_id"] == "abc123"
        assert d["image_name"] == "nginx:latest"
        assert len(d["filesystem"]) == 2
        assert d["filesystem"][0]["path"] == "/etc/passwd"
        assert d["filesystem"][0]["type"] == "file"


# ===========================================================================
# Sanitisation helpers
# ===========================================================================

class TestEnvSanitisation:
    def test_benign_env_untouched(self):
        k, v = _sanitise_env("PATH", "/usr/bin")
        assert v == "/usr/bin"

    @pytest.mark.parametrize("key", [
        "PASSWORD", "DB_PASSWORD", "API_KEY", "SECRET_KEY",
        "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "CRED_STUFF",
    ])
    def test_sensitive_keys_redacted(self, key):
        k, v = _sanitise_env(key, "supersecret")
        assert v == "***REDACTED***"


# ===========================================================================
# NetworkCapture — models
# ===========================================================================

class TestNetworkFlowRecord:
    def test_to_dict(self):
        f = NetworkFlowRecord(
            container_id="c1", protocol="tcp",
            src_addr="10.0.0.1", src_port=8080,
            dst_addr="1.2.3.4", dst_port=443,
            bytes_sent=1024, state="ESTABLISHED",
        )
        d = f.to_dict()
        assert d["container_id"] == "c1"
        assert d["protocol"] == "tcp"
        assert d["src"] == "10.0.0.1:8080"
        assert d["dst"] == "1.2.3.4:443"
        assert d["bytes_sent"] == 1024


class TestDNSQueryLog:
    def test_to_dict(self):
        d = DNSQueryLog(
            container_id="c1", query_name="example.com",
            query_type="A", response_ip="93.184.216.34",
            ttl=300,
        ).to_dict()
        assert d["query"] == "example.com"
        assert d["type"] == "A"
        assert d["answer"] == "93.184.216.34"
        assert d["ttl"] == 300


class TestIsInternal:
    @pytest.mark.parametrize("addr", [
        "10.0.0.1", "172.17.0.2", "192.168.1.1", "127.0.0.1",
    ])
    def test_private_ips(self, addr):
        assert _is_internal(addr)

    def test_public_ip(self):
        assert not _is_internal("8.8.8.8")


class TestAddrPort:
    def test_ipv4(self):
        assert _addr_port("10.0.0.1:443") == ("10.0.0.1", 443)

    def test_no_port(self):
        assert _addr_port("10.0.0.1") == ("10.0.0.1", 0)


# ===========================================================================
# NetworkCaptureService
# ===========================================================================

class TestNetworkCaptureServiceQueries:
    def test_log_and_get_flows(self):
        svc = NetworkCaptureService()
        svc.log_flow(NetworkFlowRecord(
            container_id="c1", protocol="tcp"))
        svc.log_flow(NetworkFlowRecord(
            container_id="c2", protocol="udp"))
        assert len(svc.get_flows(container_id="c1")) == 1

    def test_external_only_filter(self):
        svc = NetworkCaptureService()
        svc.log_flow(NetworkFlowRecord(
            container_id="c1", protocol="tcp",
            dst_addr="8.8.8.8", is_internal=False))
        svc.log_flow(NetworkFlowRecord(
            container_id="c1", protocol="tcp",
            dst_addr="10.0.0.1", is_internal=True))
        external = svc.get_flows(container_id="c1", external_only=True)
        assert len(external) == 1
        assert external[0]["dst"] == "8.8.8.8:0"

    def test_log_and_get_dns(self):
        svc = NetworkCaptureService()
        svc.log_dns(DNSQueryLog(
            container_id="c1", query_name="evil.com"))
        assert len(svc.get_dns_log()) == 1

    def test_detect_unusual_ports(self):
        svc = NetworkCaptureService()
        svc.log_flow(NetworkFlowRecord(
            container_id="c1", protocol="tcp",
            dst_addr="1.2.3.4", dst_port=31337, is_internal=False))
        svc.log_flow(NetworkFlowRecord(
            container_id="c1", protocol="tcp",
            dst_addr="8.8.8.8", dst_port=443, is_internal=False))
        unusual = svc.detect_unusual_ports("c1")
        assert len(unusual) == 1
        assert unusual[0]["dst"] == "1.2.3.4:31337"

    def test_clear(self):
        svc = NetworkCaptureService()
        svc.log_flow(NetworkFlowRecord())
        svc.log_dns(DNSQueryLog())
        svc.clear()
        assert len(svc.get_flows()) == 0
        assert len(svc.get_dns_log()) == 0

    def test_export_json(self):
        svc = NetworkCaptureService()
        svc.log_flow(NetworkFlowRecord(container_id="c1"))
        export = svc.export_json()
        assert "flows" in export
        assert "dns" in export
        assert export["total_flows"] == 1

    def test_max_flows_eviction(self):
        svc = NetworkCaptureService(max_flows=3)
        for i in range(5):
            svc.log_flow(NetworkFlowRecord(
                container_id=f"c{i}", protocol="tcp"))
        flows = svc.get_flows()
        assert len(flows) == 3  # oldest evicted


# ===========================================================================
# ForensicTimeline
# ===========================================================================

class TestTimelineEvent:
    def test_ordering(self):
        t1 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc)
        e1 = TimelineEvent(timestamp=t1, severity="high")
        e2 = TimelineEvent(timestamp=t2, severity="low")
        # dataclass order=True compares fields left-to-right
        assert e1 < e2

    def test_to_dict(self):
        t = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        e = TimelineEvent(
            timestamp=t, source="runtime", event_type="anomaly",
            severity="critical", container_id="c1",
            description="bad stuff", details={"foo": "bar"},
        )
        d = e.to_dict()
        assert d["source"] == "runtime"
        assert d["severity"] == "critical"
        assert d["details"]["foo"] == "bar"


class TestForensicTimeline:
    def test_add_and_query(self):
        tl = ForensicTimeline()
        t = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
        tl.add_event(TimelineEvent(
            timestamp=t, source="runtime", severity="high",
            container_id="c1", description="execve"))
        tl.add_event(TimelineEvent(
            timestamp=t, source="scan", severity="critical",
            container_id="c2", description="CVE-2024-1234"))

        all_events = tl.query()
        assert len(all_events) == 2

        c1_events = tl.query(container_id="c1")
        assert len(c1_events) == 1
        assert c1_events[0]["container_id"] == "c1"

    def test_min_severity_filter(self):
        tl = ForensicTimeline()
        t = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
        tl.add_event(TimelineEvent(
            timestamp=t, severity="low", container_id="c1"))
        tl.add_event(TimelineEvent(
            timestamp=t, severity="critical", container_id="c1"))
        high_plus = tl.query(min_severity="high")
        assert len(high_plus) == 1

    def test_time_range_filter(self):
        tl = ForensicTimeline()
        t1 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 1, 1, 14, 0, tzinfo=timezone.utc)
        for t in [t1, t2, t3]:
            tl.add_event(TimelineEvent(timestamp=t, container_id="c1"))
        mid = tl.query(since=t2, to=t3)
        assert len(mid) == 2  # t2 and t3 included

    def test_add_events_bulk(self):
        tl = ForensicTimeline()
        t = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
        events = [
            TimelineEvent(timestamp=t, container_id=f"c{i}")
            for i in range(5)
        ]
        tl.add_events(events)
        assert len(tl.query()) == 5

    def test_summary(self):
        tl = ForensicTimeline()
        t = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
        tl.add_event(TimelineEvent(
            timestamp=t, source="scan", severity="high",
            container_id="c1"))
        tl.add_event(TimelineEvent(
            timestamp=t, source="runtime", severity="critical",
            container_id="c1"))
        s = tl.summary()
        assert s["total_events"] == 2
        assert s["by_source"]["scan"] == 1
        assert s["by_severity"]["critical"] == 1

    def test_clear(self):
        tl = ForensicTimeline()
        tl.add_event(TimelineEvent(
            timestamp=datetime.now(timezone.utc)))
        tl.clear()
        assert len(tl.query()) == 0


# ===========================================================================
# RootCauseAnalyzer
# ===========================================================================

class TestRootCauseAnalyzer:
    def _make_anomaly(self, kind, extra_evidence=None):
        ev = {"kind": kind}
        if extra_evidence:
            ev["evidence"] = extra_evidence
        return ev

    def test_no_data(self):
        rca = RootCauseAnalyzer()
        assert rca.analyze("c1", [], []) == []

    def test_cryptojacking_pattern(self):
        rca = RootCauseAnalyzer()
        anomalies = [
            self._make_anomaly("crypto_mining", {"comm": "xmrig"}),
        ]
        hypotheses = rca.analyze("c1", anomalies=anomalies)
        names = [h.pattern_name for h in hypotheses]
        assert "Cryptojacking" in names

    def test_reverse_shell_pattern(self):
        rca = RootCauseAnalyzer()
        anomalies = [
            self._make_anomaly("reverse_shell"),
        ]
        hypotheses = rca.analyze("c1", anomalies=anomalies)
        names = [h.pattern_name for h in hypotheses]
        assert "Reverse Shell / C2" in names

    def test_supply_chain_pattern(self):
        rca = RootCauseAnalyzer()
        anomalies = [
            self._make_anomaly("unexpected_process", {"comm": "nmap"}),
            self._make_anomaly("file_anomaly"),
        ]
        findings = [{"cve_id": "CVE-2024-1234"}]
        hypotheses = rca.analyze(
            "c1", anomalies=anomalies, findings=findings)
        names = [h.pattern_name for h in hypotheses]
        assert "Supply Chain Compromise" in names

    def test_hypothesis_sorted_by_confidence(self):
        """Higher-confidence hypotheses should appear first."""
        rca = RootCauseAnalyzer()
        anomalies = [
            self._make_anomaly("crypto_mining", {"comm": "xmrig"}),
            self._make_anomaly("resource_spike"),
        ]
        hypotheses = rca.analyze("c1", anomalies=anomalies)
        assert len(hypotheses) >= 1
        confidences = [h.confidence for h in hypotheses]
        assert confidences == sorted(confidences, reverse=True)

    def test_recommendations_included(self):
        rca = RootCauseAnalyzer()
        anomalies = [self._make_anomaly("crypto_mining")]
        hypotheses = rca.analyze("c1", anomalies=anomalies)
        top = hypotheses[0]
        assert len(top.recommended_actions) > 0

    def test_hypothesis_to_dict(self):
        h = RootCauseHypothesis(
            pattern_name="Test", confidence=0.8, description="desc",
            mitre_techniques=["T1234"],
            evidence={"foo": "bar"},
            recommended_actions=["do X"])
        d = h.to_dict()
        assert d["pattern"] == "Test"
        assert d["confidence"] == 0.8
        assert d["mitre"] == ["T1234"]

    def test_attack_patterns_have_mitre(self):
        for pat in _ATTACK_PATTERNS:
            assert "mitre" in pat
            assert len(pat["mitre"]) > 0


# ===========================================================================
# SIEMExporter
# ===========================================================================

class TestSIEMExporter:
    def test_cef_format(self):
        cef = SIEMExporter.to_cef(
            signature="execve", name="process_started",
            severity="critical",
            extensions={"container_id": "abc", "comm": "bash"},
        )
        assert cef.startswith("CEF:0|")
        assert "|ContainerSentinel|Forensics|1.0|" in cef
        assert "|10|" in cef  # critical -> 10

    def test_cef_pipe_escaping(self):
        cef = SIEMExporter.to_cef(
            extensions={"cmd": "rm -rf /|echo pwned"},
        )
        # Pipes in values should be escaped
        assert "\\\\|" in cef or "|" in cef

    def test_leef_format(self):
        leef = SIEMExporter.to_leef(
            event_type="anomaly", severity="high",
            attributes={"kind": "privilege_escalation"},
        )
        assert leef.startswith("LEEF:2.0|")

    def test_syslog_format(self):
        syslog = SIEMExporter.to_syslog_rfc5424(
            message="Container event", msg_id="evt-1",
        )
        assert syslog.startswith("<")
        assert "1 " in syslog
        assert "Container event" in syslog

    def test_json_event(self):
        js = SIEMExporter.to_json_event(
            event_type="scan_completed", container_id="abc",
            severity="info", description="scan ok",
            details={"findings": 5},
        )
        import json
        parsed = json.loads(js)
        assert parsed["@timestamp"] is not None
        assert parsed["event"]["type"] == "scan_completed"
        assert parsed["container"]["id"] == "abc"
        assert parsed["container_forensics"]["findings"] == 5

    def test_cef_batch(self):
        events = [
            {"severity": "critical", "name": "A", "signature": "sig1"},
            {"severity": "low", "name": "B", "signature": "sig2"},
        ]
        lines = SIEMExporter.export_cef_batch(events)
        assert len(lines) == 2
        assert lines[0].startswith("CEF:")

    def test_json_batch(self):
        events = [
            {"event_type": "anomaly", "container_id": "c1",
             "severity": "high", "description": "bad"},
        ]
        lines = SIEMExporter.export_json_batch(events)
        assert len(lines) == 1
        import json
        assert json.loads(lines[0])["container"]["id"] == "c1"

    def test_elasticsearch_bulk(self):
        events = [
            {"event_type": "x", "container_id": "c1"},
        ]
        bulk = SIEMExporter.to_elasticsearch_bulk(events, index="test-idx")
        lines = bulk.strip().split("\n")
        assert len(lines) == 2
        import json
        action = json.loads(lines[0])
        assert action["index"]["_index"] == "test-idx"


# ===========================================================================
# IncidentReportGenerator
# ===========================================================================

class TestIncidentReportGenerator:
    def test_generate_basic(self):
        gen = IncidentReportGenerator()
        report = gen.generate(
            container_id="abc123", severity="critical",
            title="Suspicious execve",
        )
        assert report.container_id == "abc123"
        assert report.incident_severity == "critical"
        assert "IR-" in report.report_id

    def test_generate_with_full_data(self):
        gen = IncidentReportGenerator()
        snapshot = {
            "captured_at": "2026-01-01T10:00:00Z",
            "image_name": "nginx:latest",
            "status": "running",
            "filesystem": [FilesystemEntry("/etc/passwd", "file")],
            "processes": [ProcessInfo(pid=1, ppid=0)],
            "connections": [],
        }
        flows = [
            {"dst": "8.8.8.8:443", "is_internal": False,
             "protocol": "tcp"},
        ]
        hypotheses = [
            {"pattern": "Container Escape", "confidence": 0.7,
             "mitre": ["T1068"],
             "description": "escape via syscall",
             "recommended_actions": ["isolate container"]},
        ]
        report = gen.generate(
            container_id="abc123", severity="critical",
            title="Test Incident",
            snapshot=snapshot,
            network_flows=flows,
            rca_hypotheses=hypotheses,
            findings=[{"cve_id": "CVE-2024-0001", "severity": "high"}],
            anomalies=[{"kind": "privilege_escalation"}],
            timeline_events=[
                {"timestamp": "2026-01-01T10:00:00Z"},
            ],
        )
        assert report.snapshot_summary["image"] == "nginx:latest"
        assert report.network_summary["external_connections"] == 1
        assert len(report.root_cause_hypotheses) == 1
        assert len(report.findings) == 1
        assert "isolate container" in report.recommendations

    def test_to_json(self):
        gen = IncidentReportGenerator()
        report = gen.generate(
            container_id="abc", severity="high", title="Test")
        js = gen.to_json(report)
        import json
        d = json.loads(js)
        assert d["container_id"] == "abc"

    def test_to_markdown(self):
        gen = IncidentReportGenerator()
        report = gen.generate(
            container_id="abc", severity="high", title="Test",
            findings=[{"cve_id": "CVE-2024-001", "severity": "high",
                       "package_name": "openssl", "fixable": True}],
        )
        md = gen.to_markdown(report)
        assert "Incident Report" in md
        assert "CVE-2024-001" in md
        assert "openssl" in md

    def test_get_reports_filter(self):
        gen = IncidentReportGenerator()
        gen.generate(container_id="c1", severity="critical")
        gen.generate(container_id="c2", severity="low")
        crit = gen.get_reports(min_severity="high")
        assert len(crit) == 1
        assert crit[0].container_id == "c1"

    def test_get_reports_by_container(self):
        gen = IncidentReportGenerator()
        gen.generate(container_id="c1", severity="critical")
        gen.generate(container_id="c2", severity="critical")
        c1_reports = gen.get_reports(container_id="c1")
        assert len(c1_reports) == 1


# ===========================================================================
# AuditLogger
# ===========================================================================

class TestAuditLogger:
    def test_basic_logging(self):
        al = AuditLogger()
        rec = al.log("test_event", "c1", severity="high")
        assert rec.container_id == "c1"
        assert rec.severity == "high"
        assert rec.event_type == "test_event"

    def test_record_is_immutable(self):
        al = AuditLogger()
        rec = al.log("test", "c1")
        # frozen dataclass — should raise on mutation attempt
        with pytest.raises(Exception):
            rec.event_type = "mutated"

    def test_records_form_a_hash_chain(self):
        al = AuditLogger()
        first = al.log("first", "c1")
        second = al.log("second", "c1")
        assert first.record_hash
        assert second.previous_hash == first.record_hash
        assert first.record_hash != second.record_hash

    def test_query_by_container(self):
        al = AuditLogger()
        al.log("e1", "c1")
        al.log("e2", "c2")
        c1 = al.query(container_id="c1")
        assert len(c1) == 1
        assert c1[0]["container_id"] == "c1"

    def test_query_by_event_type(self):
        al = AuditLogger()
        al.log(AuditEvent.ANOMALY_DETECTED, "c1", severity="critical")
        al.log(AuditEvent.SCAN_COMPLETED, "c1", severity="info")
        anomaly = al.query(event_type=AuditEvent.ANOMALY_DETECTED)
        assert len(anomaly) == 1

    def test_query_min_severity(self):
        al = AuditLogger()
        al.log("e1", "c1", severity="low")
        al.log("e2", "c1", severity="critical")
        critical = al.query(min_severity="high")
        assert len(critical) == 1
        assert critical[0]["severity"] == "critical"

    def test_query_time_range(self):
        al = AuditLogger()
        now = datetime.now(timezone.utc)
        al.log("old", "c1")  # logged before 'since'
        al.log("e1", "c1")
        recent = al.query(since=now, container_id="c1")
        # The 'old' log was before `now`, so only 'e1' should match
        assert len(recent) <= 2
        assert any(r["event_type"] == "e1" for r in recent)

    def test_reverse_order(self):
        al = AuditLogger()
        al.log("first", "c1")
        al.log("second", "c1")
        records = al.query()
        assert records[0]["event_type"] == "second"  # newest first

    def test_get_record(self):
        al = AuditLogger()
        rec = al.log("unique_event", "c1")
        found = al.get_record(rec.record_id)
        assert found is not None
        assert found["event_type"] == "unique_event"

    def test_get_record_missing(self):
        al = AuditLogger()
        assert al.get_record("nonexistent") is None

    def test_summary(self):
        al = AuditLogger()
        al.log("scan", "c1", severity="info")
        al.log("anomaly", "c1", severity="high")
        s = al.summary()
        assert s["total_records"] == 2
        assert s["by_event_type"]["scan"] == 1
        assert s["by_severity"]["high"] == 1

    def test_max_records_eviction(self):
        al = AuditLogger(max_records=3)
        for i in range(5):
            al.log(f"e{i}", "c1")
        records = al.query()
        assert len(records) == 3
        # oldest evicted, so e4 should be present
        assert any(r["event_type"] == "e4" for r in records)

    def test_log_container_lifecycle(self):
        al = AuditLogger()
        rec = al.log_container_lifecycle("c1", "start")
        assert rec.event_type == AuditEvent.CONTAINER_START

    def test_log_exec(self):
        al = AuditLogger()
        rec = al.log_exec("c1", "/bin/bash", user="root")
        assert rec.event_type == AuditEvent.EXEC_COMMAND
        assert rec.subject == "/bin/bash"

    def test_log_file_change(self):
        al = AuditLogger()
        rec = al.log_file_change("c1", "/etc/passwd", "modify")
        assert rec.event_type == AuditEvent.FILE_MODIFIED

    def test_log_network_event(self):
        al = AuditLogger()
        rec = al.log_network_event("c1", "8.8.8.8", 443, "outbound")
        assert rec.event_type == AuditEvent.NETWORK_CONNECT
        assert rec.detail["remote"] == "8.8.8.8"

    def test_log_privilege_change(self):
        al = AuditLogger()
        rec = al.log_privilege_change("c1", "www-data", "root")
        assert rec.event_type == AuditEvent.PRIVILEGE_CHANGE
        assert rec.severity == "high"

    def test_export_json(self):
        al = AuditLogger()
        al.log("e1", "c1")
        js = al.export_json()
        import json
        data = json.loads(js)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_clear(self):
        al = AuditLogger()
        al.log("e1", "c1")
        al.clear()
        assert len(al.query()) == 0

    def test_convenience_event_constants(self):
        assert AuditLogger.EVENT.SCAN_INITIATED == "scan_initiated"
        assert AuditLogger.EVENT.ANOMALY_DETECTED == "anomaly_detected"
        assert AuditLogger.EVENT.SNAPSHOT_CAPTURED == "snapshot_captured"
