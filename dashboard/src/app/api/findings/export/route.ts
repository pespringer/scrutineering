import { dashboardResponse } from "../../_lib/backend";

export async function GET(request: Request) {
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/findings/export${query}`, request);
}
