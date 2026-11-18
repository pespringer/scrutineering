// Refuse state-changing requests that a browser sent from another site (CSRF).
// Plain JavaScript so scripts/tests can import it with `node --test`.

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * True when a state-changing request came from another site.
 *
 * Browsers mark every request with `Sec-Fetch-Site`; older ones still send `Origin` on a POST. A request
 * with neither header did not come from a browser (curl, the e2e script), so no other site could have
 * made it on a user's behalf.
 *
 * @param {string} method
 * @param {{ get(name: string): string | null }} headers
 * @returns {boolean}
 */
export function crossSiteMutation(method, headers) {
  if (SAFE_METHODS.has(method.toUpperCase())) return false;
  const site = headers.get("sec-fetch-site");
  if (site) return site !== "same-origin";
  const origin = headers.get("origin");
  if (!origin) return false;
  let originHost;
  try {
    originHost = new URL(origin).host;
  } catch {
    return true; // includes the opaque origin "null"
  }
  const forwardedHost = headers.get("x-forwarded-host")?.split(",")[0].trim();
  return originHost !== (forwardedHost || headers.get("host"));
}
