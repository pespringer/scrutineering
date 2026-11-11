import { getScanHistory } from "@/lib/seed";
import { dashboardResponse } from "../_lib/backend";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const limit = parseInt(url.searchParams.get("limit") || "20");
  return dashboardResponse(`/api/dashboard/scans?limit=${limit}`, () => getScanHistory(limit));
}
