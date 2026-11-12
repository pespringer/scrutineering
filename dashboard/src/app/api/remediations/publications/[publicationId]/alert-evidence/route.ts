import { dashboardMutationResponse } from "../../../../_lib/backend";

export async function POST(request: Request, { params }: { params: Promise<{ publicationId: string }> }) {
  const { publicationId } = await params;
  return dashboardMutationResponse(`/api/dashboard/remediations/publications/${publicationId}/alert-evidence`, request);
}
