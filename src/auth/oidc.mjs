import { createPrincipal } from "./authorization.mjs";

export function validateOidcClaims(claims, { issuer, audience, now = Date.now(), leewaySeconds = 60 } = {}) {
  if (!claims || typeof claims !== "object") throw new Error("OIDC claims are required");
  if (issuer && claims.iss !== issuer) throw new Error("OIDC issuer mismatch");
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (audience && !audiences.includes(audience)) throw new Error("OIDC audience mismatch");
  const nowSeconds = Math.floor(now / 1000);
  if (!Number.isFinite(claims.exp) || claims.exp < nowSeconds - leewaySeconds) throw new Error("OIDC token is expired");
  if (claims.nbf !== undefined && claims.nbf > nowSeconds + leewaySeconds) throw new Error("OIDC token is not active");
  return createPrincipal({
    id: claims.sub,
    roles: claims.roles || claims.realm_access?.roles || [],
    tenantIds: claims.tenant_ids || claims.tenantIds || [],
  });
}

export async function verifyOidcToken(token, tokenVerifier, options) {
  if (typeof tokenVerifier !== "function") throw new TypeError("tokenVerifier is required");
  const claims = await tokenVerifier(token);
  return validateOidcClaims(claims, options);
}
