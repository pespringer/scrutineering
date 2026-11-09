import { authorize, createPrincipal } from "./authorization.mjs";

export function parseApiKeys(value = "") {
  if (!value) return {};
  let parsed;
  try { parsed = JSON.parse(value); } catch { throw new Error("PLANNER_API_KEYS_JSON must be valid JSON"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("PLANNER_API_KEYS_JSON must be an object");
  }
  return Object.fromEntries(Object.entries(parsed).map(([key, claims]) => [key, createPrincipal({
    id: claims?.principal, roles: claims?.roles, tenantIds: claims?.tenantIds,
  })]));
}

export function authenticateApiKey(suppliedKey, { apiKey = "", apiKeys = {} } = {}) {
  if (typeof suppliedKey !== "string" || suppliedKey.length === 0) return null;
  if (apiKeys[suppliedKey]) return apiKeys[suppliedKey];
  if (apiKey && suppliedKey === apiKey) {
    return createPrincipal({ id: "api-key-service", roles: ["planner", "ci", "rollout"], tenantIds: ["*"] });
  }
  return null;
}

export function authorizeApiRequest(principal, policy) {
  if (!principal) return { allowed: false, code: "unauthorized" };
  return authorize(principal, policy);
}
