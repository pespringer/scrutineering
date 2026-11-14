export interface ScanResult {
  scan_id: string;
  image_id?: number;
  image_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'partial';
  started_at: string;
  completed_at?: string;
  findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  archived?: boolean;
  scanner_versions?: Record<string, string>;
  vulnerability_db_versions?: Record<string, string>;
  error_message?: string | null;
}

export interface Page<T> {
  items: T[];
  limit: number;
  offset: number;
  count: number;
  total: number;
}

export interface VulnerabilityFinding {
  id: number;
  fingerprint: string;
  cve_id: string | null;
  package_name: string;
  package_version: string | null;
  package_type: string | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | null;
  title: string;
  description: string | null;
  fixed_version: string | null;
  fix_available: boolean;
  first_seen: string;
  last_seen: string;
  remediated: boolean;
  resolved_at?: string | null;
  reopened_at?: string | null;
  lifecycle_status?: 'open' | 'resolved';
  acknowledged?: boolean;
  assigned_to?: string | null;
  suppressed?: boolean;
  suppression?: {
    id: number;
    reason: string;
    created_by: string;
    created_at: string | null;
    expires_at: string | null;
  } | null;
}

export interface PostureSummary {
  total_scanned_images: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  fixable_count: number;
  last_scan_at: string | null;
  last_scan_status: string | null;
}

export interface ImageDetail {
  id: number;
  registry: string;
  repo_name: string;
  tag: string;
  last_scan_at: string | null;
  last_scan_id: string | null;
  open_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface SeverityTrend {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}
