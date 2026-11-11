import { backendJson, dashboardResponse, trustedIdentityHeaders } from "../../_lib/backend";

export async function POST(request: Request) {
  const body = await request.text();
  return dashboardResponse("/api/dashboard/remediations/preview", async () => backendJson("/api/dashboard/remediations/preview", { method: "POST", body, headers: { "content-type": "application/json", ...trustedIdentityHeaders(request) } }), request);
}
