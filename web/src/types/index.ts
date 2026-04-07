export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface ScanFinding {
  id: number;
  scan_id: string;
  image_id: number;
  fingerprint: string;
  package_name: string;
  package_version: string | null;
  package_type: string | null;
  cve_id: string | null;
  title: string;
  description: string | null;
  severity: Severity | null;
  source: string;
  fixed_version: string | null;
  fix_available: boolean;
  first_seen: string;
  last_seen: string;
  remediated: boolean;
}

export interface ImageInfo {
  id: number;
  registry: string;
  repo_name: string;
  tag: string;
  full_name: string;
  last_scan_at: string | null;
  last_scan_id: string | null;
  active: boolean;
}

export interface ScanRecord {
  id: number;
  scan_id: string;
  image_id: number;
  started_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
  status: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface SeverityTrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface PostureSummary {
  total_scanned_images: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  fixable_count: number;
  last_scan_timestamp: string | null;
}
