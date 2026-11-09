export function loadOidcConfig(env = process.env) {
  const issuer = String(env.OIDC_ISSUER || "").trim();
  const audience = String(env.OIDC_AUDIENCE || "").trim();
  if (!issuer || !audience) throw new Error("OIDC_ISSUER and OIDC_AUDIENCE are required");
  let url;
  try { url = new URL(issuer); } catch { throw new Error("OIDC_ISSUER must be an absolute URL"); }
  if (url.protocol !== "https:") throw new Error("OIDC_ISSUER must use HTTPS");
  return { issuer: url.toString().replace(/\/$/, ""), audience };
}
