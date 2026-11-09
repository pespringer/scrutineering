const rules = {
  "/v1/plans": { findings: "array" },
  "/v1/pull-requests": { idempotencyKey: "string", plan: "object" },
  "/v1/ci/checks": { checks: "array" },
  "/v1/rollout/evaluate": { teamId: "string", riskLevel: "string" },
};

export function validatePlannerRequest(route, payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { valid: false, message: "Request body must be a JSON object." };
  }
  for (const [field, type] of Object.entries(rules[route] || {})) {
    const value = payload[field];
    const valid = type === "array"
      ? Array.isArray(value)
      : typeof value === type && value !== null && (type !== "string" || value.trim() !== "");
    if (!valid) {
      const description = type === "array" ? "an array" : `a non-empty ${type}`;
      return { valid: false, message: `Expected body.${field} to be ${description}.` };
    }
  }
  return { valid: true };
}
