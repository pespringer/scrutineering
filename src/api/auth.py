from fastapi import Request
import hmac


def groups_from_header(value: str) -> list[str]:
    """The comma list the dashboard forwards in `x-authenticated-roles`, whatever the proxy's separator."""
    return [group.strip() for group in value.split(",") if group.strip()]


def roles_for_groups(groups: list[str], mapping: dict[str, list[str]]) -> list[str]:
    """A user's roles: the union of their groups' roles, or the group names when there is no mapping."""
    if not mapping:
        return list(dict.fromkeys(groups))
    return list(dict.fromkeys(role for group in groups for role in mapping.get(group, [])))


def supplied_api_key(request: Request) -> str:
    bearer = request.headers.get("authorization", "")
    if bearer.startswith("Bearer "):
        return bearer[7:]
    return request.headers.get("x-api-key", "")


def is_api_key_authorized(request: Request, expected: str) -> bool:
    supplied = supplied_api_key(request)
    return bool(expected) and bool(supplied) and hmac.compare_digest(supplied, expected)
