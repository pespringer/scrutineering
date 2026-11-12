import { dashboardResponse } from "../../../../_lib/backend";

export async function GET(request: Request, { params }: { params: Promise<{ publicationId: string }> }) {
  const { publicationId } = await params;
  return dashboardResponse(`/api/dashboard/remediations/publications/${publicationId}/evidence-export`, () => ({}), request);
}
