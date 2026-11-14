import { dashboardResponse } from "../../_lib/backend";

export async function GET(request: Request) {
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/runtime/events${query}`, () => ({ status: "unavailable", checkpoint_offset: null, events: [] }), request);
}
