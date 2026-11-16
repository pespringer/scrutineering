import { dashboardMutationResponse, dashboardResponse } from "../_lib/backend";

export async function GET(request: Request) {
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/remediations${query}`, request);
}

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/remediations", request, 201);
}
