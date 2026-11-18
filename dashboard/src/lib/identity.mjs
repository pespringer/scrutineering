// Who is signed in, from the headers a forward-auth proxy adds (docs/design/forward-auth.md).
// Plain JavaScript so scripts/tests can import it with `node --test`.

/** Header names per proxy. Header lookups ignore case. */
export const PRESETS = {
  scrutineering: {
    user: "x-authenticated-sub",
    email: "x-authenticated-email",
    groups: "x-authenticated-roles",
    separator: ",",
  },
  authelia: { user: "remote-user", email: "remote-email", groups: "remote-groups", separator: "," },
  authentik: {
    user: "x-authentik-username",
    email: "x-authentik-email",
    groups: "x-authentik-groups",
    separator: "|",
  },
  "oauth2-proxy": {
    user: "x-auth-request-user",
    email: "x-auth-request-email",
    groups: "x-auth-request-groups",
    separator: ",",
  },
};

/** @param {string | undefined} name */
export function preset(name) {
  const chosen = PRESETS[name || "scrutineering"];
  if (!chosen) throw new Error(`DASHBOARD_AUTH_HEADERS must be one of ${Object.keys(PRESETS).join(", ")}`);
  return chosen;
}

/**
 * The signed-in user, or null when the request did not come through the ingress with one.
 *
 * @param {Record<string, string | undefined>} env
 * @param {{ get(name: string): string | null }} headers
 * @returns {{ sub: string, email: string | null, groups: string[] } | null}
 */
export function proxyIdentity(env, headers) {
  const names = preset(env.DASHBOARD_AUTH_HEADERS);
  const secret = env.DASHBOARD_TRUSTED_PROXY_SECRET;
  if (!secret || headers.get("x-dashboard-proxy-secret") !== secret) return null;
  const sub = headers.get(names.user)?.trim();
  if (!sub) return null;
  const groups = (headers.get(names.groups) || "")
    .split(names.separator)
    .map((group) => group.trim())
    .filter((group) => group && !group.includes(","));
  return { sub, email: headers.get(names.email)?.trim() || null, groups };
}

/**
 * The identity in the fixed form the API reads, with the groups as a comma list.
 *
 * @param {{ sub: string, email: string | null, groups: string[] }} identity
 * @param {string} secret
 */
export function apiIdentityHeaders(identity, secret) {
  /** @type {Record<string, string>} */
  const headers = {
    "x-dashboard-proxy-secret": secret,
    "x-authenticated-sub": identity.sub,
    "x-authenticated-roles": identity.groups.join(","),
  };
  if (identity.email) headers["x-authenticated-email"] = identity.email;
  return headers;
}
