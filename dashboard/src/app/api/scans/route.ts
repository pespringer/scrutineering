import { backendJson, dashboardResponse, trustedIdentityHeaders } from "../_lib/backend";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const limit = parseInt(url.searchParams.get("limit") || "20");
  const query = new URLSearchParams(url.searchParams);
  query.set("limit", String(limit));
  return dashboardResponse(`/api/dashboard/scans?${query}`, undefined, req);
}

export async function POST(req: Request) {
  if (!process.env.DASHBOARD_API_URL) {
    return Response.json({ error: "scan_controls_require_live_api" }, { status: 503 });
  }
  try {
    return Response.json(await backendJson("/api/dashboard/scans", {
      method: "POST",
      headers: { "content-type": "application/json", ...trustedIdentityHeaders(req) },
      body: await req.text(),
    }), { status: 202 });
  } catch {
    return Response.json({ error: "scan_queue_unavailable" }, { status: 503 });
  }
}
