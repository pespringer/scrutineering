import { dashboardMutationResponse } from "../../_lib/backend";

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/runtime/discovery", request, 202);
}
