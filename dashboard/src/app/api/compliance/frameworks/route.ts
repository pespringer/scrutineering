import { dashboardResponse } from "../../_lib/backend";

export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/compliance/frameworks", undefined, request);
}
