const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000/api';

async function fetchWithError(url: string): Promise<any> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error ${res.status}: ${res.statusText}`);
  return res.json();
}

export async function fetchPostureSummary(): Promise<any> {
  return fetchWithError(`${API_BASE}/posture/summary`);
}

export async function fetchSeverityTrend(days: number = 30): Promise<any[]> {
  return fetchWithError(`${API_BASE}/posture/trend?days=${days}`);
}

export async function fetchScanHistory(limit: number = 20): Promise<any[]> {
  return fetchWithError(`${API_BASE}/scans?limit=${limit}`);
}

export async function fetchImages(): Promise<any[]> {
  return fetchWithError(`${API_BASE}/images`);
}

export async function fetchImageById(imageId: string): Promise<any> {
  return fetchWithError(`${API_BASE}/images/${imageId}`);
}

export async function fetchFindingsByImage(imageId: string, severity?: string): Promise<any[]> {
  const params = new URLSearchParams();
  if (severity) params.set('severity', severity);
  return fetchWithError(`${API_BASE}/images/${imageId}/findings?${params}`);
}
