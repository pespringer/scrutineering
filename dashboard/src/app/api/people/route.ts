import { dashboardResponse } from "../_lib/backend";

/** Everyone who has signed in (admin only; the API checks). */
export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/people", request);
}
