/** Fetch helpers for the dashboard's own /api routes, with readable error messages. */

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

/** Pull a message out of an API error body: FastAPI's detail[].msg or detail, or our `error` field. */
export function errorMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== "object") return fallback;
  const body = payload as { detail?: unknown; error?: unknown };
  if (Array.isArray(body.detail)) {
    const first = body.detail[0] as { msg?: string } | undefined;
    if (first?.msg) return first.msg.replace(/^Value error, /, "");
  }
  if (typeof body.detail === "string") return body.detail.replaceAll("_", " ");
  if (typeof body.error === "string") return body.error.replaceAll("_", " ");
  return fallback;
}

async function parse<T>(response: Response, fallback: string): Promise<T> {
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw new ApiError(errorMessage(payload, fallback), response.status);
  return payload as T;
}

export async function getJson<T>(url: string): Promise<T> {
  return parse<T>(await fetch(url, { cache: "no-store" }), `Request failed (${url})`);
}

export async function postJson<T>(url: string, body?: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return parse<T>(response, "Request failed");
}
