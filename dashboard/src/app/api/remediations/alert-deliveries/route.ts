import { dashboardResponse } from "../../_lib/backend";

export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/remediations/alert-deliveries", () => ({ items: [], count: 0 }), request);
}
