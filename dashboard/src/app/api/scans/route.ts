import { dashboardMutationResponse, dashboardResponse } from "../_lib/backend";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const limit = parseInt(url.searchParams.get("limit") || "20");
  const query = new URLSearchParams(url.searchParams);
  query.set("limit", String(limit));
  return dashboardResponse(`/api/dashboard/scans?${query}`, req);
}

// Pass the API's status and body through, so validation errors (422) reach the
// form instead of being reported as an unavailable queue.
export async function POST(req: Request) {
  return dashboardMutationResponse("/api/dashboard/scans", req, 202);
}
