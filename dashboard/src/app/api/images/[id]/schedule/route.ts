import { dashboardMutationResponse, dashboardResponse } from "../../../_lib/backend";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return dashboardResponse(`/api/dashboard/images/${id}/schedule`, undefined, req);
}

export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return dashboardMutationResponse(`/api/dashboard/images/${id}/schedule`, req);
}
