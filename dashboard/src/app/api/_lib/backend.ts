import { NextResponse } from "next/server";
import { apiIdentityHeaders, proxyIdentity } from "@/lib/identity.mjs";

class BackendError extends Error {
  constructor(
    public readonly status: number,
    public readonly payload: unknown = null,
  ) {
    super(`dashboard backend returned ${status}`);
  }
}

export async function backendJson<T>(path: string, init?: RequestInit): Promise<T> {
  const base = process.env.DASHBOARD_API_URL;
  if (!base) throw new Error("DASHBOARD_API_URL is not configured");

  const response = await fetch(`${base.replace(/\/$/, "")}${path}`, {
    ...init,
    cache: "no-store",
    headers: {
      "x-api-key": process.env.DASHBOARD_API_KEY || "",
      ...(init?.headers || {}),
    },
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new BackendError(response.status, payload);
  }
  return response.json() as Promise<T>;
}

/** The signed-in user's identity for the API, when the dashboard runs behind a forward-auth proxy. */
export function trustedIdentityHeaders(request: Request): Record<string, string> {
  if (process.env.DASHBOARD_AUTH_MODE !== "trusted-proxy") return {};
  const identity = proxyIdentity(process.env, request.headers);
  return identity ? apiIdentityHeaders(identity, process.env.DASHBOARD_TRUSTED_PROXY_SECRET || "") : {};
}

export async function dashboardResponse<T>(path: string, request?: Request) {
  try {
    const payload = await backendJson<T>(path, request ? { headers: trustedIdentityHeaders(request) } : undefined);
    return NextResponse.json(payload);
  } catch (error) {
    if (error instanceof BackendError) {
      return NextResponse.json(error.payload || { error: "dashboard_backend_rejected" }, { status: error.status });
    }
    return NextResponse.json({ error: "dashboard_backend_unavailable" }, { status: 503 });
  }
}

export async function dashboardMutationResponse<T>(path: string, request: Request, status = 200) {
  try {
    const payload = await backendJson<T>(path, {
      method: "POST",
      body: await request.text(),
      headers: { "content-type": "application/json", ...trustedIdentityHeaders(request) },
    });
    return NextResponse.json(payload, { status });
  } catch (error) {
    if (error instanceof BackendError) {
      return NextResponse.json(error.payload || { error: "dashboard_backend_rejected" }, { status: error.status });
    }
    return NextResponse.json({ error: "dashboard_backend_unavailable" }, { status: 503 });
  }
}

/** Headers a download keeps on its way through: what it is, its name, and Scrutineering's own metadata. */
const DOWNLOAD_HEADERS = ["content-type", "content-disposition"];

/** Pass a file from the API to the browser unchanged (SBOMs and other exports), keeping its bytes exact. */
export async function dashboardDownload(path: string, request: Request) {
  const base = process.env.DASHBOARD_API_URL;
  if (!base) return NextResponse.json({ error: "dashboard_backend_unavailable" }, { status: 503 });
  try {
    const response = await fetch(`${base.replace(/\/$/, "")}${path}`, {
      cache: "no-store",
      headers: { "x-api-key": process.env.DASHBOARD_API_KEY || "", ...trustedIdentityHeaders(request) },
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      return NextResponse.json(payload || { error: "dashboard_backend_rejected" }, { status: response.status });
    }
    const headers = new Headers();
    response.headers.forEach((value, name) => {
      if (DOWNLOAD_HEADERS.includes(name) || name.startsWith("x-scrutineering-")) headers.set(name, value);
    });
    return new NextResponse(await response.arrayBuffer(), { status: 200, headers });
  } catch {
    return NextResponse.json({ error: "dashboard_backend_unavailable" }, { status: 503 });
  }
}
