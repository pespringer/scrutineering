import { backendJson, dashboardResponse, trustedIdentityHeaders } from "../_lib/backend";

export async function GET(req: Request) {
  return dashboardResponse("/api/dashboard/production-operations", () => ({
    panels: [],
    scorecard: { status: "unknown", checks: {}, passed: 0, total: 0 },
    receiver_delivery: { enabled: false, deferred: true },
  }), req);
}
