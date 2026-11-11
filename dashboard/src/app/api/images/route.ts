import { getImages, getImageById, getFindingsByImage } from "@/lib/seed";
import { dashboardResponse } from "../_lib/backend";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  const severity = url.searchParams.get("severity");

  if (id) {
    return dashboardResponse(`/api/dashboard/images/${id}${severity ? `?severity=${encodeURIComponent(severity)}` : ""}`, () => {
      const img = getImageById(id);
      if (!img) return { error: "not_found" };
      return { image: img, findings: getFindingsByImage(id, severity || undefined) };
    });
  }

  const query = new URLSearchParams(url.searchParams);
  if (!query.has("limit")) query.set("limit", "20");
  return dashboardResponse(`/api/dashboard/images?${query}`, () => {
    const items = getImages();
    return { items, limit: items.length, offset: 0, count: items.length, total: items.length };
  });
}
