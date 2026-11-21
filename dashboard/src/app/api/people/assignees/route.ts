import { dashboardResponse } from "../../_lib/backend";

/** Who findings can be assigned to: subject and email only. */
export async function GET(request: Request) {
  return dashboardResponse("/api/dashboard/people/assignees", request);
}
