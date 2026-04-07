import { NextResponse } from "next/server";
import { getImages, getImageById, getFindingsByImage } from "@/lib/seed";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  const severity = url.searchParams.get("severity");

  if (id) {
    const img = getImageById(id);
    if (!img) return NextResponse.json({ error: "not_found" }, { status: 404 });
    const findings = getFindingsByImage(id, severity || undefined);
    return NextResponse.json({ image: img, findings });
  }

  return NextResponse.json(getImages());
}
