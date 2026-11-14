import { dashboardResponse } from "../../_lib/backend";

export async function GET(req: Request) {
  return dashboardResponse("/api/dashboard/posture/summary", undefined, req);
}
