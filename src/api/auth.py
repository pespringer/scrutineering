from fastapi import Request


def supplied_api_key(request: Request) -> str:
    bearer = request.headers.get("authorization", "")
    if bearer.startswith("Bearer "): return bearer[7:]
    return request.headers.get("x-api-key", "")


def is_api_key_authorized(request: Request, expected: str) -> bool:
    return bool(expected) and supplied_api_key(request) == expected
