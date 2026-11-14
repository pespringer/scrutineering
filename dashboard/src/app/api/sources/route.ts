import { dashboardMutationResponse, dashboardResponse } from "../_lib/backend";

export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/sources", undefined, request);
}

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/sources", request, 201);
}
