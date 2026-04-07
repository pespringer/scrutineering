import type { SeverityTrendPoint, PostureSummary, ImageInfo, ScanRecord } from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:3100/api/companies/3e7ec1c0-5251-41c8-8e10-ea343cf35ad5";

export async function fetchPostureSummary(): Promise<PostureSummary> {
  const res = await fetch(`${API_BASE}/posture/summary`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch posture summary: ${res.status}`);
  return res.json();
}

export async function fetchSeverityTrend(): Promise<SeverityTrendPoint[]> {
  const res = await fetch(`${API_BASE}/posture/trend`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch severity trend: ${res.status}`);
  return res.json();
}

export async function fetchImages(): Promise<ImageInfo[]> {
  const res = await fetch(`${API_BASE}/images`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch images: ${res.status}`);
  return res.json();
}

export async function fetchScans(): Promise<ScanRecord[]> {
  const res = await fetch(`${API_BASE}/scans`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch scans: ${res.status}`);
  return res.json();
}

export async function fetchImageFindings(imageId: number) {
  const params = new URLSearchParams({ image_id: String(imageId) });
  const res = await fetch(`${API_BASE}/findings?${params}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch findings: ${res.status}`);
  return res.json() as Promise<any[]>;
}
