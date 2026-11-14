import { dashboardMutationResponse, dashboardResponse } from "../../_lib/backend";

export async function GET(request: Request) {
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/compliance/reports${query}`, undefined, request);
}

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/compliance/reports", request, 201);
}
