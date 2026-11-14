import { dashboardResponse } from "../_lib/backend";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  const severity = url.searchParams.get("severity");

  if (id) {
    return dashboardResponse(`/api/dashboard/images/${id}${severity ? `?severity=${encodeURIComponent(severity)}` : ""}`, undefined, req);
  }

  const query = new URLSearchParams(url.searchParams);
  if (!query.has("limit")) query.set("limit", "20");
  return dashboardResponse(`/api/dashboard/images?${query}`, undefined, req);
}
