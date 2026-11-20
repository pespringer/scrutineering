import { dashboardMutationResponse, dashboardResponse } from "../../_lib/backend";

export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/compliance/exports", request);
}

/** Request an export (security-operator; the API checks the role and the range). */
export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/compliance/exports", request, 202);
}
