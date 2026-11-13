import { backendJson, trustedIdentityHeaders } from "../../../_lib/backend";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const query = new URL(req.url).search;
  try {
    return Response.json(await backendJson(`/api/dashboard/scans/${encodeURIComponent(id)}/findings${query}`, { headers: trustedIdentityHeaders(req) }));
  } catch {
    return Response.json({ error: "scan_findings_unavailable" }, { status: 503 });
  }
}
