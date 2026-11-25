import { dashboardResponse } from "../../../_lib/backend";

export async function GET(request: Request) {
  const given = new URL(request.url).searchParams;
  const query = new URLSearchParams({ repository: given.get("repository") ?? "", tag: given.get("tag") ?? "" });
  return dashboardResponse(`/api/dashboard/registry/tags/detail?${query}`, request);
}
