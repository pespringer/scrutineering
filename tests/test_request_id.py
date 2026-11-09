import asyncio

from src.api.app import app


def test_request_id_middleware_is_registered():
    assert any(getattr(middleware, "cls", None).__name__ == "BaseHTTPMiddleware" for middleware in app.user_middleware)
