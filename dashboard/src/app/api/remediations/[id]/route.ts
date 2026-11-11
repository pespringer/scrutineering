import { backendJson, dashboardResponse, trustedIdentityHeaders } from "../../_lib/backend";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return dashboardResponse(`/api/dashboard/remediations/${id}`, () => backendJson(`/api/dashboard/remediations/${id}`, { headers: trustedIdentityHeaders(request) }), request);
}
