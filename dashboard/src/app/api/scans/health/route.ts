import { dashboardResponse } from "../../_lib/backend";

export async function GET(req: Request) {
  const query = new URL(req.url).search;
  return dashboardResponse(`/api/dashboard/scans/health${query}`, () => ({ total: 0, by_status: {}, terminal: 0, terminal_rate: 0, degraded: false }), req);
}
