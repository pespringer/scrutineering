import { NextResponse } from "next/server";
import { getScanHistory } from "@/lib/seed";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const limit = parseInt(url.searchParams.get("limit") || "20");
  return NextResponse.json(getScanHistory(limit));
}
