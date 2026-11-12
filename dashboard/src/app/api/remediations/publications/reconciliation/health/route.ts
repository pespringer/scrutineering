import { dashboardResponse } from "../../../../_lib/backend";

export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/remediations/publications/reconciliation/health", () => ({ status: "unavailable", last_run: null }), request);
}
