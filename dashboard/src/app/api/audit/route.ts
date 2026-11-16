import { dashboardResponse } from "../_lib/backend";

export async function GET(req: Request) {
  const query = new URL(req.url).search;
  return dashboardResponse(`/api/dashboard/audit${query}`, req);
}
