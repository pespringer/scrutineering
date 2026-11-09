from fastapi import Request
import hmac


def supplied_api_key(request: Request) -> str:
    bearer = request.headers.get("authorization", "")
    if bearer.startswith("Bearer "): return bearer[7:]
    return request.headers.get("x-api-key", "")


def is_api_key_authorized(request: Request, expected: str) -> bool:
    supplied = supplied_api_key(request)
    return bool(expected) and bool(supplied) and hmac.compare_digest(supplied, expected)
