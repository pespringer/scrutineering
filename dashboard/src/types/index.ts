export interface ScanResult {
  scan_id: string;
  image_id?: number;
  image_name: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled" | "partial";
  phase?: string;
  task_id?: string | null;
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
  file_path?: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" | null;
  title: string;
  description: string | null;
  fixed_version: string | null;
  fix_available: boolean;
  first_seen: string;
  last_seen: string;
  resolved_at?: string | null;
  reopened_at?: string | null;
  lifecycle_status?: "open" | "resolved";
  acknowledged?: boolean;
  assigned_to?: string | null;
  remediation_id?: number | null;
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
  /** Display reference, e.g. `nginx:1.27` or `registry:5000/team/app:1.0`. */
  name: string;
  repo_name: string;
  tag: string;
  last_scan_at: string | null;
  last_scan_id: string | null;
  open_findings: number;
  resolved_findings?: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  source?: ImageSource | null;
}

export interface ImageSource {
  repository: string;
  ref: string;
  dockerfile_path: string;
  build_context: string;
  build_args: Record<string, string>;
  test_command: string[] | null;
  updated_by: string | null;
  updated_at: string | null;
}

export interface RegistryTag {
  repository: string;
  tag: string;
  digest: string | null;
  size: number;
  image_id: number | null;
  scan_id: string | null;
  scan_status: string | null;
  last_scan_at: string | null;
  security_status: "clean" | "issues_found" | "scanning" | "scan_failed" | "not_scanned";
  open_findings: number;
  critical_count: number;
  high_count: number;
  image_name: string;
}

export interface RegistryInventory {
  registry: { host: string; url: string; internal_host?: string; reachable: boolean };
  repositories: string[];
  tags: RegistryTag[];
  summary: {
    repositories: number;
    tags: number;
    scanned: number;
    not_scanned: number;
    scanning: number;
    issues_found: number;
    clean: number;
  };
}

export interface SeverityTrend {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DashboardSession {
  authenticated: boolean;
  subject?: string;
  email?: string | null;
  roles?: string[];
}

export interface RemediationEvent {
  id: number;
  event_type: string;
  sequence: number;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface RemediationPublication {
  id: number;
  provider: string;
  repository: string;
  status: string;
  url: string | null;
  verification_status: string | null;
  scan_status: string | null;
  post_merge_scan_id: string | null;
  verification_detail?: Record<string, unknown>;
  findings_before: number | null;
  findings_after: number | null;
  rollback_command: string[] | null;
}

export interface RemediationAction {
  action_type: string;
  file_path?: string | null;
  before_value: string | null;
  after_value: string | null;
  detail?: { description?: string; packages?: Record<string, string>; finding_ids?: number[] };
}

export interface RemediationVerification {
  targeted: number;
  still_present: string[];
  new_critical_or_high: {
    cve_id: string | null;
    package_name: string;
    package_version: string | null;
    severity: string;
  }[];
  candidate_findings: number;
}

/** One status column; transitions are defined in src/remediation/state_machine.py. */
export type RemediationStatus =
  | "proposed"
  | "approved"
  | "building"
  | "verifying"
  | "needs_acceptance"
  | "ready"
  | "completed"
  | "failed"
  | "cancelled";

export interface RemediationRecord {
  id: number;
  image_id: number;
  status: RemediationStatus;
  status_label: string;
  error_message?: string | null;
  approved_by?: string | null;
  source_commit?: string | null;
  patch?: string | null;
  candidate_image?: string | null;
  candidate_digest?: string | null;
  verification?: RemediationVerification | null;
  finding_count: number;
  open_finding_count?: number;
  resolved_finding_count?: number;
  resolution_status?: string;
  actions: RemediationAction[];
  publications: RemediationPublication[];
}
