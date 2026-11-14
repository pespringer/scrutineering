import { dashboardMutationResponse, dashboardResponse } from "../_lib/backend";

export async function GET(request: Request) {
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/backup-evidence${query}`, undefined, request);
}

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/backup-evidence/execute", request, 202);
}
