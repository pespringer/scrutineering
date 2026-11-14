import { backendJson, dashboardResponse, trustedIdentityHeaders } from "../../../_lib/backend";

export async function GET(request: Request, context: { params: Promise<{ taskId: string }> }) {
  const { taskId } = await context.params;
  return dashboardResponse(
    `/api/dashboard/deployment-observation/preflight/${taskId}`,
    () => backendJson(`/api/dashboard/deployment-observation/preflight/${taskId}`, { headers: trustedIdentityHeaders(request) }),
    request,
  );
}
