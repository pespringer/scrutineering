import { loadOidcConfig } from "./oidc-config.mjs";
import { discoverOidcProvider } from "./oidc-discovery.mjs";
import { createJwksVerifier } from "./jwks-verifier.mjs";
import { verifyOidcToken } from "./oidc.mjs";

export async function createOidcVerifier(env = process.env, options = {}) {
  const config = loadOidcConfig(env);
  const metadata = await discoverOidcProvider({ issuer: config.issuer, fetchImpl: options.fetchImpl, timeoutMs: options.timeoutMs });
  const verifyJwt = createJwksVerifier({ jwksUri: metadata.jwksUri, fetchImpl: options.fetchImpl, verifySignature: options.verifySignature });
  return (token) => verifyOidcToken(token, verifyJwt, { issuer: config.issuer, audience: config.audience });
}
