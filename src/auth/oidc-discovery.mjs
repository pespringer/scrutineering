export async function discoverOidcProvider({ issuer, fetchImpl = fetch, timeoutMs = 5000 } = {}) {
  if (!issuer || !/^https:\/\//.test(issuer)) throw new Error("OIDC issuer must use HTTPS");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`, { signal: controller.signal });
    if (!response.ok) throw new Error(`OIDC discovery failed with status ${response.status}`);
    const metadata = await response.json();
    if (metadata.issuer !== issuer.replace(/\/$/, "") || !metadata.jwks_uri || !/^https:\/\//.test(metadata.jwks_uri)) throw new Error("OIDC discovery metadata is invalid");
    return { issuer: metadata.issuer, jwksUri: metadata.jwks_uri, authorizationEndpoint: metadata.authorization_endpoint || null };
  } finally { clearTimeout(timer); }
}
