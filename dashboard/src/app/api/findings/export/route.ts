import { dashboardResponse } from "../../_lib/backend";

export async function GET(request: Request) {
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/findings/export${query}`, () => ({ format: "scrutineering-findings-v1", count: 0, sha256: "", records: [] }), request);
}
