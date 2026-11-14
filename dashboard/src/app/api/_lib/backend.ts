import { NextResponse } from "next/server";

class BackendError extends Error {
  constructor(public readonly status: number) {
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
  if (!response.ok) throw new BackendError(response.status);
  return response.json() as Promise<T>;
}

export function trustedIdentityHeaders(request: Request): Record<string, string> {
  const headers: Record<string, string> = {};
  const configuredSecret = process.env.DASHBOARD_TRUSTED_PROXY_SECRET;
  const suppliedSecret = request.headers.get("x-dashboard-proxy-secret");
  if (configuredSecret && suppliedSecret === configuredSecret) {
    for (const name of ["x-authenticated-sub", "x-authenticated-email", "x-authenticated-roles"]) {
      const value = request.headers.get(name);
      if (value) headers[name] = value;
    }
    headers["x-dashboard-proxy-secret"] = configuredSecret;
  }
  return headers;
}

export async function dashboardResponse<T>(
  path: string,
  _fallback: (() => T | Promise<T>) | undefined = undefined,
  request?: Request,
) {
  try {
    const payload = process.env.DASHBOARD_API_URL
      ? await backendJson<T>(path, request ? { headers: trustedIdentityHeaders(request) } : undefined)
      : await Promise.reject(new Error("DASHBOARD_API_URL is not configured"));
    return NextResponse.json(payload);
  } catch (error) {
    if (error instanceof BackendError) {
      return NextResponse.json({ error: "dashboard_backend_rejected" }, { status: error.status });
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
      return NextResponse.json({ error: "dashboard_backend_rejected" }, { status: error.status });
    }
    return NextResponse.json({ error: "dashboard_backend_unavailable" }, { status: 503 });
  }
}
