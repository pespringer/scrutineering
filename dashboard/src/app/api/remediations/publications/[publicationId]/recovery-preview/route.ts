import { dashboardResponse } from "../../../../_lib/backend";

export async function GET(request: Request, context: { params: Promise<{ publicationId: string }> }) {
  const { publicationId } = await context.params;
  return dashboardResponse(`/api/dashboard/remediations/publications/${publicationId}/recovery-preview`, () => ({}), request);
}
