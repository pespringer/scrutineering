import { NextResponse } from "next/server";
import { getSeverityTrend } from "@/lib/seed";
import { dashboardResponse } from "../../_lib/backend";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const days = parseInt(url.searchParams.get("days") || "30");
  return dashboardResponse(`/api/dashboard/posture/trend?days=${days}`, () => getSeverityTrend(days));
}
