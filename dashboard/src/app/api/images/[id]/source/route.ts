import { backendJson, trustedIdentityHeaders } from "../../../_lib/backend";
import { NextResponse } from "next/server";

async function forward(request: Request, id: string, method: "PUT" | "DELETE") {
  try {
    const body = method === "PUT" ? await request.text() : undefined;
    const payload = await backendJson(`/api/dashboard/images/${encodeURIComponent(id)}/source`, {
      method,
      body,
      headers: { ...(body ? { "content-type": "application/json" } : {}), ...trustedIdentityHeaders(request) },
    });
    return NextResponse.json(payload);
  } catch (error) {
    const status = (error as { status?: number }).status;
    const payload = (error as { payload?: unknown }).payload;
    return NextResponse.json(payload || { error: "image_source_unavailable" }, { status: status || 503 });
  }
}

export async function PUT(request: Request, { params }: { params: Promise<{ id: string }> }) {
  return forward(request, (await params).id, "PUT");
}

export async function DELETE(request: Request, { params }: { params: Promise<{ id: string }> }) {
  return forward(request, (await params).id, "DELETE");
}
