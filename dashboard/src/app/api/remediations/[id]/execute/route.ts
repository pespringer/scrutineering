import { dashboardMutationResponse } from "../../../_lib/backend";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return dashboardMutationResponse(`/api/dashboard/remediations/${id}/execute`, request, 202);
}
