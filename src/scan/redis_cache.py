"""Adapter for sharing scan cache entries through a Redis-compatible client."""

import json
import hashlib


class RedisScanCache:
    def __init__(self, client, ttl_seconds: int = 3600, prefix: str = "scrutineering:scan:", max_entry_bytes: int = 5_000_000):
        if ttl_seconds < 1 or ttl_seconds > 604800: raise ValueError("ttl_seconds must be between 1 and 604800")
        if not prefix or any(char.isspace() for char in prefix): raise ValueError("cache prefix must be non-empty and whitespace-free")
        if max_entry_bytes < 1: raise ValueError("max_entry_bytes must be positive")
        self.client, self.ttl_seconds, self.prefix, self.max_entry_bytes = client, ttl_seconds, prefix, max_entry_bytes

    def _key(self, scanner: str, image: str) -> str:
        digest = hashlib.sha256(f"{scanner}\0{image}".encode()).hexdigest()
        return f"{self.prefix}{digest}"

    async def get(self, scanner: str, image: str):
        value = await self.client.get(self._key(scanner, image))
        if not value: return None
        try: return json.loads(value)
        except (TypeError, json.JSONDecodeError): return None

    async def set(self, scanner: str, image: str, findings):
        encoded = json.dumps(findings, sort_keys=True)
        if len(encoded.encode()) > self.max_entry_bytes: raise ValueError("scan cache entry exceeds size limit")
        await self.client.set(self._key(scanner, image), encoded, ex=self.ttl_seconds)


class SyncRedisScanCache(RedisScanCache):
    """Synchronous counterpart for Celery's thread-based scanner workers."""

    def get_sync(self, scanner: str, image: str):
        value = self.client.get(self._key(scanner, image))
        if not value: return None
        try: return json.loads(value)
        except (TypeError, json.JSONDecodeError): return None

    def set_sync(self, scanner: str, image: str, findings):
        encoded = json.dumps(findings, sort_keys=True)
        if len(encoded.encode()) > self.max_entry_bytes: raise ValueError("scan cache entry exceeds size limit")
        self.client.set(self._key(scanner, image), encoded, ex=self.ttl_seconds)
