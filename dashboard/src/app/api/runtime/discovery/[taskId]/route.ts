import { dashboardResponse } from "../../../_lib/backend";

export async function GET(request: Request, context: { params: Promise<{ taskId: string }> }) {
  const { taskId } = await context.params;
  return dashboardResponse(`/api/dashboard/runtime/discovery/${encodeURIComponent(taskId)}`, undefined, request);
}
