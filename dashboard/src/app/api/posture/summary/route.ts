import { getPostureSummary } from "@/lib/seed";
import { dashboardResponse } from "../../_lib/backend";

export async function GET() {
  return dashboardResponse("/api/dashboard/posture/summary", getPostureSummary);
}
