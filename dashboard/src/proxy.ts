import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { proxyIdentity } from "@/lib/identity.mjs";
import { crossSiteMutation } from "@/lib/sameOrigin.mjs";

const SIGN_IN_REQUIRED = "Sign-in required: open Scrutineering through its sign-in proxy.";

export function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
  if (path === "/api/health") return NextResponse.next();
  // In every auth mode: another site must not be able to make the dashboard act for its user.
  if (path.startsWith("/api/") && crossSiteMutation(request.method, request.headers)) {
    return NextResponse.json({ error: "cross_site_request_refused" }, { status: 403 });
  }
  const mode = process.env.DASHBOARD_AUTH_MODE || "local";
  if (mode === "local") return NextResponse.next();

  let identity = null;
  try {
    identity = mode === "trusted-proxy" ? proxyIdentity(process.env, request.headers) : null;
  } catch (error) {
    // An unknown DASHBOARD_AUTH_HEADERS preset: refuse everything rather than guess.
    const message = error instanceof Error ? error.message : "invalid DASHBOARD_AUTH_HEADERS";
    return NextResponse.json({ error: "invalid_configuration", detail: message }, { status: 503 });
  }
  if (mode !== "trusted-proxy") {
    return NextResponse.json({ error: "invalid_configuration", detail: "DASHBOARD_AUTH_MODE" }, { status: 503 });
  }
  if (identity) return NextResponse.next();
  if (path.startsWith("/api/")) {
    return NextResponse.json({ error: "dashboard_authentication_required" }, { status: 401 });
  }
  return new NextResponse(SIGN_IN_REQUIRED, { status: 401, headers: { "content-type": "text/plain" } });
}

// Every page and route, except Next's own static files.
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
