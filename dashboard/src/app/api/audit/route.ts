import { dashboardResponse } from "../_lib/backend";

export async function GET(req: Request) {
  const query = new URL(req.url).search;
  return dashboardResponse(`/api/dashboard/audit${query}`, () => ({ items: [], limit: 25, offset: 0, count: 0, total: 0 }), req);
}
