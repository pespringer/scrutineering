import { dashboardMutationResponse } from "../../_lib/backend";

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/remediations/recovery-bulk-status", request);
}
