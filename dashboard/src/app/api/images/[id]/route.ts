import { getImageById, getFindingsByImage } from "@/lib/seed";
import { dashboardResponse } from "../../_lib/backend";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return dashboardResponse(`/api/dashboard/images/${id}`, () => {
    const img = getImageById(id);
    if (!img) return { error: "not_found" };
    return { image: img, findings: getFindingsByImage(id) };
  });
}
