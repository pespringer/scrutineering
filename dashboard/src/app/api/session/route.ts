import { NextResponse } from "next/server";
import { dashboardResponse } from "../_lib/backend";

/** The caller's identity and roles from the API, plus where to sign out (DASHBOARD_LOGOUT_URL). */
export async function GET(req: Request) {
  const response = await dashboardResponse("/api/dashboard/session", req);
  const body = await response.json();
  const logout = process.env.DASHBOARD_LOGOUT_URL || "";
  const logoutUrl = /^https?:\/\//.test(logout) ? logout : null;
  return NextResponse.json({ ...body, logout_url: logoutUrl }, { status: response.status });
}
