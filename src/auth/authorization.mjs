/** Small, provider-neutral authorization primitives for API handlers.
 *
 * Authentication providers should translate their verified claims into this
 * shape. This module deliberately does not parse or trust raw JWTs.
 */

export function createPrincipal({ id, roles = [], tenantIds = [] }) {
  if (typeof id !== "string" || id.trim() === "") throw new TypeError("principal id is required");
  return {
    id,
    roles: [...new Set(roles)].filter((role) => typeof role === "string"),
    tenantIds: [...new Set(tenantIds)].filter((tenant) => typeof tenant === "string"),
  };
}

export function authorize(principal, { role, tenantId } = {}) {
  if (!principal) return { allowed: false, code: "unauthorized" };
  if (role && !principal.roles.includes(role)) {
    return { allowed: false, code: "forbidden", reason: `role ${role} is required` };
  }
  if (tenantId && !principal.tenantIds.includes(tenantId)) {
    return { allowed: false, code: "tenant_forbidden", reason: "tenant is outside the principal scope" };
  }
  return { allowed: true };
}
