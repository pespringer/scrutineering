const base64url = (value) => Buffer.from(value, "base64url").toString("utf8");

export function createJwksVerifier({ jwksUri, fetchImpl = fetch, verifySignature, cacheTtlMs = 300000 } = {}) {
  if (!jwksUri || typeof verifySignature !== "function") throw new TypeError("jwksUri and verifySignature are required");
  if (!Number.isInteger(cacheTtlMs) || cacheTtlMs < 1000 || cacheTtlMs > 86400000) throw new Error("cacheTtlMs must be between 1000 and 86400000");
  let cached = null;
  return async function verify(token) {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) throw new Error("JWT must contain three segments");
    const header = JSON.parse(base64url(parts[0]));
    const claims = JSON.parse(base64url(parts[1]));
    if (!header.kid || !header.alg || header.alg === "none") throw new Error("JWT header is incomplete or insecure");
    if (!cached || cached.expiresAt <= Date.now()) {
      const response = await fetchImpl(jwksUri);
      if (!response.ok) throw new Error(`JWKS fetch failed with status ${response.status}`);
      const payload = await response.json();
      if (!Array.isArray(payload.keys) || payload.keys.length > 1000) throw new Error("JWKS key set is invalid");
      cached = { keys: payload.keys, expiresAt: Date.now() + cacheTtlMs };
    }
    let key = cached.keys.find((candidate) => candidate.kid === header.kid);
    if (!key) {
      cached = null;
      return verify(token);
    }
    if (!key || !(await verifySignature({ header, claims, key, signed: `${parts[0]}.${parts[1]}`, signature: parts[2] }))) throw new Error("JWT signature verification failed");
    return claims;
  };
}
