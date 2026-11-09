import asyncio

from src.scan.registry import resolve_image_digest_with_fallback


def test_digest_fallback_uses_remote_resolver(monkeypatch):
    async def local(_image): raise RuntimeError("no docker")
    async def remote(_image, _token=None): return "sha256:" + "e" * 64
    monkeypatch.setattr("src.scan.registry.resolve_image_digest", local)
    monkeypatch.setattr("src.scan.registry.resolve_registry_digest", lambda *args, **kwargs: "sha256:" + "e" * 64)
    assert asyncio.run(resolve_image_digest_with_fallback("alpine:latest")) == "sha256:" + "e" * 64
