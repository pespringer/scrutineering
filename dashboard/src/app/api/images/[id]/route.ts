import { NextResponse } from "next/server";
import { getImageById, getFindingsByImage } from "@/lib/seed";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const img = getImageById(id);
  if (!img) return NextResponse.json({ error: "not_found" }, { status: 404 });
  const findings = getFindingsByImage(id);
  return NextResponse.json({ image: img, findings });
}
