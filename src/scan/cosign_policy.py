from __future__ import annotations


def load_cosign_policy(env: dict[str, str] | None = None) -> dict[str, object]:
    values = env or {}
    identity = str(values.get("COSIGN_CERTIFICATE_IDENTITY", "")).strip()
    issuer = str(values.get("COSIGN_OIDC_ISSUER", "")).strip()
    production = values.get("NODE_ENV") == "production"
    if production and (not identity or not issuer):
        raise ValueError("production cosign policy requires identity and OIDC issuer")
    if issuer and not issuer.startswith("https://"):
        raise ValueError("cosign OIDC issuer must use HTTPS")
    return {"identity": identity or None, "issuer": issuer or None, "required": production}
