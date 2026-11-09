import { loadOidcConfig } from "./oidc-config.mjs";
import { discoverOidcProvider } from "./oidc-discovery.mjs";
import { createJwksVerifier } from "./jwks-verifier.mjs";
import { verifyOidcToken } from "./oidc.mjs";

export async function createOidcVerifier(env = process.env, options = {}) {
  const config = loadOidcConfig(env);
  const metadata = await discoverOidcProvider({ issuer: config.issuer, fetchImpl: options.fetchImpl, timeoutMs: options.timeoutMs });
  const verifyJwt = createJwksVerifier({ jwksUri: metadata.jwksUri, fetchImpl: options.fetchImpl, verifySignature: options.verifySignature });
  const leewaySeconds = Number(env.OIDC_LEEWAY_SECONDS || 60);
  if (!Number.isInteger(leewaySeconds) || leewaySeconds < 0 || leewaySeconds > 600) throw new Error("OIDC_LEEWAY_SECONDS must be between 0 and 600");
  return (token) => verifyOidcToken(token, verifyJwt, { issuer: config.issuer, audience: config.audience, leewaySeconds });
}
