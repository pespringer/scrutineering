import asyncio
from src.scan.redis_cache import RedisScanCache


def test_redis_scan_cache_round_trip():
    values = {}
    class Client:
        async def get(self, key): return values.get(key)
        async def set(self, key, value, ex): values[key] = value; assert ex == 10
    cache = RedisScanCache(Client(), ttl_seconds=10)
    asyncio.run(cache.set("trivy", "image", [{"id": "CVE-1"}]))
    assert asyncio.run(cache.get("trivy", "image")) == [{"id": "CVE-1"}]
