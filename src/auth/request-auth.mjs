import { authorize, createPrincipal } from "./authorization.mjs";
import { authenticateApiKey } from "./api-keys.mjs";

function bearerToken(request) {
  const value = request?.headers?.authorization;
  return typeof value === "string" && value.startsWith("Bearer ")
    ? value.slice(7).trim()
    : "";
}

/** Authenticate API-key and provider-backed bearer credentials at one boundary. */
export async function authenticateRequest(request, {
  apiKey = "",
  apiKeys = {},
  oidcVerifier = null,
} = {}) {
  const token = bearerToken(request);
  if (token && oidcVerifier) {
    try {
      return await oidcVerifier(token);
    } catch {
      return null;
    }
  }

  const supplied = token || request?.headers?.["x-api-key"];
  return authenticateApiKey(supplied, { apiKey, apiKeys });
}

/** Build a verifier-backed planner request authenticator. */
export function createRequestAuthenticator({ apiKey = "", apiKeys = {}, oidcVerifier } = {}) {
  if (typeof oidcVerifier !== "function") throw new TypeError("oidcVerifier is required");
  return (request) => authenticateRequest(request, { apiKey, apiKeys, oidcVerifier });
}

export function authorizeAuthenticatedRequest(principal, policy) {
  return authorize(principal, policy);
}

export { createPrincipal };
