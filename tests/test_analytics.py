"""Tests for analytics and reporting components."""

import pytest

from src.analytics.compliance import ComplianceReporter, FRAMEWORKS
from src.analytics.notifications import (
    AlertMessage,
    NotificationService,
    BaseChannel,
    WebhookChannel,
    SlackChannel,
    PagerDutyChannel,
    EmailChannel,
)
from src.analytics.posture import SEVERITY_WEIGHTS


# ===========================================================================
# ComplianceReporter
# ===========================================================================

class TestComplianceReporter:
    def test_supported_frameworks(self):
        reporter = ComplianceReporter()
        for fw in ["nist", "pci_dss", "soc2", "hipaa", "gdpr"]:
            assert fw in reporter.SUPPORTED
            assert fw in FRAMEWORKS

    def test_generate_nist_report(self):
        reporter = ComplianceReporter()
        report = reporter.generate(
            "nist",
            posture_data={"total_images": 5, "findings_by_severity": {"critical": 0, "high": 2}},
            audit_data={"total_records": 100},
            anomaly_data={},
        )
        assert report["framework"] == "nist"
        assert "controls" in report
        assert report["controls_total"] > 0
        assert report["compliance_percent"] >= 0

    def test_generate_soc2_report(self):
        reporter = ComplianceReporter()
        report = reporter.generate(
            "soc2",
            posture_data={"total_images": 3, "findings_by_severity": {"critical": 0}},
            audit_data={"total_records": 50},
            anomaly_data={"total_anomalies": 2},
        )
        assert report["framework"] == "soc2"
        assert report["controls_total"] == 2  # SOC 2 has 2 controls

    def test_generate_gdpr_report(self):
        reporter = ComplianceReporter()
        report = reporter.generate(
            "gdpr",
            posture_data={"total_images": 1},
            audit_data={},
            anomaly_data={},
        )
        assert report["framework"] == "gdpr"
        assert len(report["controls"]) == 2

    def test_generate_all_compliant(self):
        reporter = ComplianceReporter()
        report = reporter.generate(
            "nist",
            posture_data={"total_images": 10, "findings_by_severity": {"critical": 0}},
            audit_data={"total_records": 500},
            anomaly_data={},
            trend_data={"mean_remediation_hours": 4},
        )
        assert report["overall_status"] == "compliant"

    def test_generate_non_compliant(self):
        """Critical CVEs open means non-compliant on CVE check."""
        reporter = ComplianceReporter()
        report = reporter.generate(
            "nist",
            posture_data={"total_images": 10, "findings_by_severity": {"critical": 5}},
            audit_data={"total_records": 5},
            anomaly_data={"privilege_escalation_events": 3},
        )
        assert report["overall_status"] == "partial"

    def test_generate_unsupported_framework_raises(self):
        reporter = ComplianceReporter()
        with pytest.raises(ValueError, match="Unsupported framework"):
            reporter.generate("iso27001")

    def test_list_reports(self):
        reporter = ComplianceReporter()
        reporter.generate("nist")
        reporter.generate("pci_dss")
        all_reports = reporter.list_reports()
        assert len(all_reports) == 2
        nist = reporter.list_reports("nist")
        assert len(nist) == 1

    def test_export_markdown(self):
        reporter = ComplianceReporter()
        report = reporter.generate(
            "nist",
            posture_data={"total_images": 1},
            audit_data={"total_records": 10},
            anomaly_data={},
        )
        md = reporter.export_markdown(report)
        assert "Compliance Report" in md
        assert report["report_id"] in md

    def test_critical_cves_check(self):
        reporter = ComplianceReporter()
        # Zero critical CVEs = pass
        r1 = reporter._check_critical_cves(
            {"findings_by_severity": {"critical": 0}}, None, None, None)
        assert r1["pass"] is True
        # Non-zero critical CVEs = fail
        r2 = reporter._check_critical_cves(
            {"findings_by_severity": {"critical": 3}}, None, None, None)
        assert r2["pass"] is False

    def test_images_scanned_check(self):
        reporter = ComplianceReporter()
        assert reporter._check_images_scanned(
            {"total_images": 5}, None, None, None)["pass"] is True
        assert reporter._check_images_scanned(
            {"total_images": 0}, None, None, None)["pass"] is False

    def test_mttr_check(self):
        reporter = ComplianceReporter()
        assert reporter._check_mttr(
            None, None, None, {"mean_remediation_hours": 10})["pass"] is True
        assert reporter._check_mttr(
            None, None, None, {"mean_remediation_hours": 48})["pass"] is False
        assert reporter._check_mttr(
            None, None, None, {})["pass"] is False

    def test_audit_check(self):
        reporter = ComplianceReporter()
        assert reporter._check_audit(
            None, {"total_records": 100}, None, None)["pass"] is True
        assert reporter._check_audit(
            None, {"total_records": 0}, None, None)["pass"] is False


# ===========================================================================
# NotificationService
# ===========================================================================

class TestAlertMessage:
    def test_to_dict(self):
        msg = AlertMessage(
            title="Test Alert",
            severity="high",
            body="Something happened",
            container_id="abc123",
        )
        d = msg.to_dict()
        assert d["title"] == "Test Alert"
        assert d["severity"] == "high"
        assert d["container_id"] == "abc123"

    def test_metadata(self):
        msg = AlertMessage(
            title="X", severity="medium", body="",
            metadata={"cve": "CVE-2024-1234"},
        )
        assert msg.metadata["cve"] == "CVE-2024-1234"


class TestBaseChannel:
    def test_min_severity_filtering(self):
        channel = BaseChannel("test", min_severity="high")
        assert channel.should_send("critical")
        assert channel.should_send("high")
        assert not channel.should_send("medium")
        assert not channel.should_send("low")


class TestWebhookChannel:
    def test_channel_properties(self):
        ch = WebhookChannel(
            url="https://example.com/hook", name="myhook",
            min_severity="medium",
        )
        assert ch.name == "myhook"
        assert ch.url == "https://example.com/hook"
        assert ch.should_send("high")


class TestSlackChannel:
    def test_channel_properties(self):
        ch = SlackChannel(
            webhook_url="https://hooks.slack.com/xxx",
            channel="#security",
            username="Sentinel",
        )
        assert ch.name == "slack"
        assert ch.channel == "#security"
        assert ch.username == "Sentinel"


class TestPagerDutyChannel:
    def test_channel_properties(self):
        ch = PagerDutyChannel(
            routing_key="abc123",
            min_severity="critical",
        )
        assert ch.name == "pagerduty"
        assert ch._min_severity == "critical"
        assert not ch.should_send("high")
        assert ch.should_send("critical")


class TestEmailChannel:
    def test_channel_properties(self):
        ch = EmailChannel(
            recipients=["ops@example.com"],
            sender="alerts@sentinel.local",
            min_severity="low",
        )
        assert ch.name == "email"
        assert ch.recipients == ["ops@example.com"]

    def test_send_without_smtp(self):
        """Without a real SMTP callback, send() just logs."""
        ch = EmailChannel(recipients=["ops@example.com"])
        msg = AlertMessage(
            title="Test", severity="high", body="Details",
            container_id="c1",
        )
        assert ch.send(msg) is True
        assert ch.sent_count == 1


class TestNotificationService:
    def test_add_channel(self):
        svc = NotificationService()
        ch = EmailChannel(recipients=["test@example.com"])
        svc.add_channel(ch)
        assert len(svc._channels) == 1

    def test_remove_channel(self):
        svc = NotificationService()
        svc.add_channel(EmailChannel(recipients=["a@b.com"]))
        removed = svc.remove_channel("email")
        assert removed == 1
        assert len(svc._channels) == 0

    def test_dispatch_to_filter_channel(self):
        svc = NotificationService()
        ch = EmailChannel(
            recipients=["test@example.com"],
            min_severity="medium",
        )
        svc.add_channel(ch)
        msg = AlertMessage(
            title="Test", severity="high", body="",
        )
        results = svc.dispatch(msg)
        assert results["email"] is True

    def test_dispatch_below_min_severity(self):
        svc = NotificationService()
        ch = EmailChannel(
            recipients=["test@example.com"],
            min_severity="critical",
        )
        svc.add_channel(ch)
        msg = AlertMessage(
            title="Test", severity="low", body="",
        )
        results = svc.dispatch(msg)
        assert results["email"] is False

    def test_dispatch_cooldown(self):
        svc = NotificationService(cooldown_seconds=60)
        ch = EmailChannel(recipients=["test@example.com"])
        svc.add_channel(ch)
        msg = AlertMessage(
            title="Duplicate", severity="high", body="",
            container_id="c1",
        )
        r1 = svc.dispatch(msg)
        assert r1["email"] is True
        # Same title+container within cooldown — suppressed
        r2 = svc.dispatch(msg)
        assert r2 == {}

    def test_different_alerts_not_cooldown(self):
        svc = NotificationService(cooldown_seconds=60)
        ch = EmailChannel(recipients=["test@example.com"])
        svc.add_channel(ch)
        msg1 = AlertMessage(
            title="Alert A", severity="high", body="",
            container_id="c1",
        )
        msg2 = AlertMessage(
            title="Alert B", severity="high", body="",
            container_id="c1",
        )
        r1 = svc.dispatch(msg1)
        r2 = svc.dispatch(msg2)
        assert r1["email"] is True
        assert r2["email"] is True

    def test_dispatch_from_dict(self):
        svc = NotificationService()
        svc.add_channel(EmailChannel(recipients=["test@example.com"]))
        results = svc.dispatch_from_dict({
            "title": "Dict Alert",
            "severity": "medium",
            "body": "Generated from dict",
            "container_id": "c2",
            "alert_id": "alert-001",
        })
        assert results["email"] is True

    def test_channel_stats(self):
        svc = NotificationService()
        ch1 = EmailChannel(recipients=["a@b.com"])
        ch2 = EmailChannel(recipients=["c@d.com"], name="email-2")
        svc.add_channel(ch1)
        svc.add_channel(ch2)
        # ch1.name and ch2.name both "email" — second one overrides name
        stats = svc.channel_stats()
        assert len(stats) >= 1

    def test_summary(self):
        svc = NotificationService()
        svc.add_channel(EmailChannel(recipients=["x@y.com"]))
        s = svc.summary()
        assert s["channels"] == 1
        assert s["total_dispatched"] == 0

    def test_dispatch_to_specific_channels(self):
        svc = NotificationService()
        ch1 = EmailChannel(recipients=["a@b.com"])
        ch2 = EmailChannel(recipients=["c@d.com"], name="email-2")
        svc.add_channel(ch1)
        svc.add_channel(ch2)
        msg = AlertMessage(
            title="Targeted", severity="high", body="",
        )
        results = svc.dispatch(msg, channels=["email"])
        assert "email" in results
        assert "email-2" not in results


# ===========================================================================
# Severity weights
# ===========================================================================

class TestSeverityWeights:
    def test_weights_defined(self):
        assert SEVERITY_WEIGHTS["critical"] == 10
        assert SEVERITY_WEIGHTS["high"] == 5
        assert SEVERITY_WEIGHTS["medium"] == 2
        assert SEVERITY_WEIGHTS["low"] == 1

    def test_critical_outweighs_others(self):
        assert SEVERITY_WEIGHTS["critical"] > SEVERITY_WEIGHTS["high"]
        assert SEVERITY_WEIGHTS["critical"] > SEVERITY_WEIGHTS["medium"]


# ===========================================================================
# API router smoke test
# ===========================================================================

class TestAnalyticsRouter:
    def test_router_prefix(self):
        from src.analytics.api import router
        assert router.prefix == "/api/analytics"
        assert len(router.routes) >= 10

    def test_frameworks_endpoint_spec(self):
        from src.analytics.api import router
        paths = [r.path for r in router.routes]
        assert "/api/analytics/compliance/frameworks" in paths
        assert "/api/analytics/posture/overview" in paths
        assert "/api/analytics/trends/overall" in paths
