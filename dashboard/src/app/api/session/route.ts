import { dashboardResponse } from "../_lib/backend";

export async function GET(req: Request) {
  return dashboardResponse("/api/dashboard/session", () => ({
    authenticated: true,
    auth_method: "standalone",
    subject: "local-developer",
    email: null,
    roles: ["dashboard"],
  }), req);
}
