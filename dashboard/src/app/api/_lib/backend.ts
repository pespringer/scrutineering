import { NextResponse } from "next/server";

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
  if (!response.ok) throw new Error(`dashboard backend returned ${response.status}`);
  return response.json() as Promise<T>;
}

export async function dashboardResponse<T>(
  path: string,
  fallback: () => T | Promise<T>,
) {
  try {
    const payload = process.env.DASHBOARD_API_URL
      ? await backendJson<T>(path)
      : await fallback();
    return NextResponse.json(payload);
  } catch {
    return NextResponse.json({ error: "dashboard_backend_unavailable" }, { status: 503 });
  }
}
