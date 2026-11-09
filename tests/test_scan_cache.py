from src.scan.cache import ScanCache


def test_scan_cache_round_trips_and_expires(tmp_path):
    cache = ScanCache(tmp_path, ttl_seconds=10)
    findings = [{"cve_id": "CVE-1", "severity": "high"}]
    image = "alpine@sha256:" + "a" * 64
    cache.set("trivy", image, findings, now=100)
    assert cache.get("trivy", image, now=105) == findings
    assert cache.get("trivy", image, now=111) is None


def test_cache_keys_separate_scanners(tmp_path):
    cache = ScanCache(tmp_path)
    cache.set("trivy", "image", [{"source": "trivy"}], now=1)
    cache.set("grype", "image", [{"source": "grype"}], now=1)
    assert cache.get("trivy", "image", now=2)[0]["source"] == "trivy"
    assert cache.get("grype", "image", now=2)[0]["source"] == "grype"
