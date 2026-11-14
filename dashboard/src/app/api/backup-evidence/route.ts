import { dashboardMutationResponse, dashboardResponse } from "../_lib/backend";

export async function GET(request: Request) {
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/backup-evidence${query}`, undefined, request);
}

export async function POST(request: Request) {
  return dashboardMutationResponse("/api/dashboard/backup-evidence/execute", request, 202);
}

export async function PUT(request: Request) {
  const backupId = new URL(request.url).searchParams.get("backup_id");
  if (!backupId) return new Response(JSON.stringify({ error: "backup_id_required" }), { status: 400, headers: { "content-type": "application/json" } });
  return dashboardMutationResponse(`/api/dashboard/backup-evidence/${encodeURIComponent(backupId)}/restore`, request, 202);
}
