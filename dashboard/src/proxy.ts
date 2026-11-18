import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { crossSiteMutation } from "@/lib/sameOrigin.mjs";

const protectedMode = "trusted-proxy";

export function proxy(request: NextRequest) {
  if (request.nextUrl.pathname === "/api/health") return NextResponse.next();
  // In every auth mode: another site must not be able to make the dashboard act for its user.
  if (request.nextUrl.pathname.startsWith("/api/") && crossSiteMutation(request.method, request.headers)) {
    return NextResponse.json({ error: "cross_site_request_refused" }, { status: 403 });
  }
  if ((process.env.DASHBOARD_AUTH_MODE || "local") === "local") return NextResponse.next();

  const configuredSecret = process.env.DASHBOARD_TRUSTED_PROXY_SECRET;
  const suppliedSecret = request.headers.get("x-dashboard-proxy-secret");
  const subject = request.headers.get("x-authenticated-sub");
  if (
    process.env.DASHBOARD_AUTH_MODE === protectedMode &&
    configuredSecret &&
    suppliedSecret === configuredSecret &&
    subject
  ) {
    return NextResponse.next();
  }

  return NextResponse.json(
    { error: "dashboard_authentication_required" },
    { status: process.env.DASHBOARD_AUTH_MODE === protectedMode ? 401 : 503 },
  );
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/scans/:path*",
    "/audit/:path*",
    "/operations/:path*",
    "/remediations/:path*",
    "/api/:path*",
  ],
};
