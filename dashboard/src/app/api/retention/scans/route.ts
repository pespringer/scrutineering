import { dashboardMutationResponse, dashboardResponse } from "../../_lib/backend";

export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/retention/scans", undefined, request);
}

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/retention/scans", request, 202);
}
