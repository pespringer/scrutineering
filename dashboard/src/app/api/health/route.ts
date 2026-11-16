// Liveness probe for this container (Dockerfile HEALTHCHECK, k8s probes): it only
// says the dashboard process is serving. Service status for people is /api/system-status.
export function GET() {
  return Response.json({ status: "ok" });
}
