import { dashboardResponse } from "../_lib/backend";

export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/registry/inventory", () => ({
    registry: { host: "localhost:5000", url: "http://localhost:5000", reachable: false },
    repositories: [],
    tags: [],
    summary: { repositories: 0, tags: 0, scanned: 0, not_scanned: 0, scanning: 0, issues_found: 0, clean: 0 },
  }), request);
}
