import { backendJson, dashboardResponse, trustedIdentityHeaders } from "../../../_lib/backend";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const body = await request.text();
  return dashboardResponse(`/api/dashboard/remediations/${id}/approval-token`, () => backendJson(`/api/dashboard/remediations/${id}/approval-token`, { method: "POST", body, headers: { "content-type": "application/json", ...trustedIdentityHeaders(request) } }), request);
}
