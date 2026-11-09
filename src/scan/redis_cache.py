"""Adapter for sharing scan cache entries through a Redis-compatible client."""

import json
import hashlib


class RedisScanCache:
    def __init__(self, client, ttl_seconds: int = 3600, prefix: str = "scrutineering:scan:"):
        if ttl_seconds < 1 or ttl_seconds > 604800: raise ValueError("ttl_seconds must be between 1 and 604800")
        if not prefix or any(char.isspace() for char in prefix): raise ValueError("cache prefix must be non-empty and whitespace-free")
        self.client, self.ttl_seconds, self.prefix = client, ttl_seconds, prefix

    def _key(self, scanner: str, image: str) -> str:
        digest = hashlib.sha256(f"{scanner}\0{image}".encode()).hexdigest()
        return f"{self.prefix}{digest}"

    async def get(self, scanner: str, image: str):
        value = await self.client.get(self._key(scanner, image))
        if not value: return None
        try: return json.loads(value)
        except (TypeError, json.JSONDecodeError): return None

    async def set(self, scanner: str, image: str, findings):
        await self.client.set(self._key(scanner, image), json.dumps(findings, sort_keys=True), ex=self.ttl_seconds)
