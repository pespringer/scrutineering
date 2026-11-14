import { dashboardMutationResponse, dashboardResponse } from "../_lib/backend";

export async function GET(request: Request) {
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/policies${query}`, undefined, request);
}

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/policies", request, 201);
}
