import { dashboardMutationResponse } from "../../_lib/backend";

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/images/bulk-archive", request);
}
