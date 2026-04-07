import { NextResponse } from "next/server";
import { getPostureSummary } from "@/lib/seed";

export async function GET() {
  return NextResponse.json(getPostureSummary());
}
