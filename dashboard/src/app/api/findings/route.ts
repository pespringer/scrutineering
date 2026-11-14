import { dashboardResponse } from "../_lib/backend";

export async function GET(request: Request) {
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/findings${query}`, () => ({ items: [], limit: 25, offset: 0, count: 0, total: 0 }), request);
}
