import { dashboardMutationResponse, dashboardResponse } from "../_lib/backend";

export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/reports", request);
}

/** Queue an on-demand report (admin only; the API checks). */
export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/reports", request, 202);
}
