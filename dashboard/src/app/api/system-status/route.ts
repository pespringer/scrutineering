import { dashboardResponse } from "../_lib/backend";

// Live status for the sidebar panel. Distinct from /api/health, which is this
// container's liveness probe and only says the dashboard process is up.
export async function GET(req: Request) {
  return dashboardResponse("/api/dashboard/system-status", req);
}
