import { dashboardResponse } from "../_lib/backend";

export async function GET(req: Request) {
  return dashboardResponse("/api/dashboard/permissions", () => ({
    roles: ["dashboard", "operator"],
    can_view: true,
    can_manage_scans: true,
    can_cancel_scans: true,
    can_remediate: false,
  }), req);
}
