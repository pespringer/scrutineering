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

// Waits between attempts when the API can't be reached (it was restarting), within an overall budget:
// a refused connection fails at once and is retried; one that hangs uses the budget up and is not.
const RETRY_DELAYS_MS = [250, 750, 1500, 2500];
const RETRY_BUDGET_MS = 10000;

/**
 * Fetch from the API, retrying a read when the API could not be reached at all. A write is never
 * retried: the API may have received it.
 */
async function fetchApi(url: string, init: RequestInit): Promise<Response> {
  const method = (init.method || "GET").toUpperCase();
  const delays = method === "GET" || method === "HEAD" ? RETRY_DELAYS_MS : [];
  const started = Date.now();
  for (const delay of delays) {
    try {
      return await fetch(url, init);
    } catch (error) {
      if (Date.now() - started + delay >= RETRY_BUDGET_MS) throw error;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  return fetch(url, init);
}

export async function backendJson<T>(path: string, init?: RequestInit): Promise<T> {
  const base = process.env.DASHBOARD_API_URL;
  if (!base) throw new Error("DASHBOARD_API_URL is not configured");

  const response = await fetchApi(`${base.replace(/\/$/, "")}${path}`, {
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
