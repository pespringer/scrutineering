import { dashboardMutationResponse } from "../../../_lib/backend";

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return dashboardMutationResponse(`/api/dashboard/policies/${id}/toggle`, request);
}
