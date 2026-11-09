import pytest

from fastapi import HTTPException
from src.scan import api


class Provider:
    def get_scan(self, scan_id):
        return {"scan_id": scan_id, "status": "completed"} if scan_id == "scan-1" else None

    def list_findings(self, **filters):
        return [{"fingerprint": "f1", "severity": filters["severity"] or "high"}, {"fingerprint": "f2"}]

    def list_alerts(self, **filters):
        return [{"id": "a1", "status": filters["status"] or "open"}]

    def list_audit(self, **filters):
        return [{"actor": filters["actor"] or "system", "event_type": filters["event_type"] or "scan_completed"}]


def test_versioned_read_api_has_consistent_pagination_and_filters():
    api.set_scan_data_provider(Provider())
    result = api.list_findings(severity="critical", image_digest=None, limit=1, offset=0)
    assert result.items == [{"fingerprint": "f1", "severity": "critical"}]
    assert result.count == 1
    assert api.list_alerts(status="open", limit=100, offset=0).items[0]["id"] == "a1"
    assert api.list_audit(actor="ci", event_type=None, limit=100, offset=0).items[0]["actor"] == "ci"


def test_scan_endpoint_returns_not_found_and_data():
    api.set_scan_data_provider(Provider())
    assert api.get_scan("scan-1")["status"] == "completed"
    with pytest.raises(HTTPException) as error:
        api.get_scan("missing")
    assert error.value.status_code == 404
