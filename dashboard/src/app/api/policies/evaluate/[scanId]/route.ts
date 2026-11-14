import { dashboardMutationResponse } from "../../../_lib/backend";

export async function POST(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  return dashboardMutationResponse(`/api/dashboard/policies/evaluate/${scanId}`, request);
}
