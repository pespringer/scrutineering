import { dashboardMutationResponse } from "../../../../_lib/backend";

export async function POST(request: Request, context: { params: Promise<{ publicationId: string }> }) {
  const { publicationId } = await context.params;
  return dashboardMutationResponse(`/api/dashboard/remediations/publications/${publicationId}/evidence`, request);
}
