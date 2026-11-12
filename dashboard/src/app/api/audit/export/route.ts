import { dashboardResponse } from "../../_lib/backend";

export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/audit/export", () => ({ format: "scrutineering-audit-v1", count: 0, records: [] }), request);
}
