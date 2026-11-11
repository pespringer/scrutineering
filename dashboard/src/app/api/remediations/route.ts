import { backendJson, dashboardResponse, trustedIdentityHeaders } from "../_lib/backend";

export async function POST(request: Request) {
  const body = await request.text();
  return dashboardResponse("/api/dashboard/remediations", async () => backendJson("/api/dashboard/remediations", { method: "POST", body, headers: { "content-type": "application/json", ...trustedIdentityHeaders(request) } }), request);
}
