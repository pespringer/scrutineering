import { backendJson, trustedIdentityHeaders } from "../../_lib/backend";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    return Response.json(await backendJson(`/api/dashboard/scans/${encodeURIComponent(id)}`, { headers: trustedIdentityHeaders(req) }));
  } catch {
    return Response.json({ error: "scan_status_unavailable" }, { status: 503 });
  }
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    return Response.json(await backendJson(`/api/dashboard/scans/${encodeURIComponent(id)}/cancel`, { method: "POST", headers: trustedIdentityHeaders(req) }));
  } catch {
    return Response.json({ error: "scan_cancellation_unavailable" }, { status: 503 });
  }
}
