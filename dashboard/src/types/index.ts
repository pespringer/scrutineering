export interface ScanResult {
  /** Only on the single-scan route: the scan's SBOM, if one was written. */
  sbom?: SbomSummary | null;
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

/** A scan's CycloneDX SBOM, as the API summarises it before download (docs/design/sbom-evidence.md). */
export interface SbomSummary {
  scan_id: string;
  format: string;
  spec_version: string | null;
  components: number;
  sha256: string;
  /** Signed with this instance's key (`key_id`); verify with the public key from /api/signing-keys. */
  signed?: boolean;
  key_id?: string | null;
  created_at: string | null;
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
  /** When runtime discovery last saw it running; `running` means within the last 30 minutes. */
  last_seen_running_at?: string | null;
  running?: boolean;
  /** On the Images list: running containers, and how many run an older build than the latest scan. */
  containers?: number;
  stale_containers?: number;
  open_findings: number;
  resolved_findings?: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  source?: ImageSource | null;
  /** The SBOM of the image's latest scan that has one. */
  sbom?: SbomSummary | null;
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

/** A remediation's copy of its image's source, taken when it was proposed. */
export type RemediationSource = Omit<ImageSource, "updated_by" | "updated_at">;

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

/** The GitHub pull request a remediation was published as. */
export interface RemediationPublication {
  id: number;
  provider: string;
  repository: string;
  status: "open" | "merged" | "closed" | "failed";
  url: string | null;
  number: number | null;
  branch: string | null;
  base_branch: string | null;
  head_commit: string | null;
  error_message: string | null;
  merged_at: string | null;
  merge_commit: string | null;
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
  | "published"
  | "completed"
  | "failed"
  | "cancelled";

/** A remediation's signed evidence bundle, as the detail route summarises it. */
export interface EvidenceSummary {
  outcome: "completed" | "failed";
  sha256: string;
  signed: boolean;
  key_id: string | null;
  created_at: string | null;
}

/** A container runtime discovery saw (docs/design/deployment-observation.md). */
export interface DeploymentContainer {
  container_id: string;
  name: string;
  image_ref: string;
  /** Against the image's latest scan; `unknown` when that scan has no digest. */
  state: "current" | "stale" | "unknown";
  running_digests: string[];
  started_at: string | null;
  last_seen_at: string | null;
  gone_at: string | null;
}

export interface ImageDeployments {
  image_id: number;
  scan_digest: string | null;
  containers: DeploymentContainer[];
  /** Gone within the last 24 hours. */
  gone: DeploymentContainer[];
}

/** A completed remediation's rollout; `fixed` is null when no fixed build has a digest. */
export interface RemediationDeployment {
  containers: number;
  fixed: number | null;
  not_fixed: string[];
}

/** Someone recorded at sign-in (GET /people). */
export interface Person {
  subject: string;
  email: string | null;
  roles: string[];
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface RemediationRecord {
  /** Only on the detail route, for a completed remediation: which containers run a fixed build. */
  deployment?: RemediationDeployment | null;
  /** Only on the detail route: the latest evidence bundle, once the remediation has ended. */
  evidence?: EvidenceSummary | null;
  id: number;
  image_id: number;
  status: RemediationStatus;
  status_label: string;
  error_message?: string | null;
  /** Who took each step, by identity-provider subject. */
  proposed_by?: string | null;
  approved_by?: string | null;
  executed_by?: string | null;
  accepted_by?: string | null;
  published_by?: string | null;
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
  /** The image's source as proposed: what the fix builds from. */
  source?: RemediationSource | null;
  /** The image's source has changed since this fix was proposed; retrying picks up the change. */
  source_changed?: boolean;
  /** `owner/name` when the image's source is on GitHub, so it can be published as a pull request. */
  publication_target?: string | null;
  publications: RemediationPublication[];
}

/** A stored report's summary (docs/design/reports-compliance.md). */
export interface ReportSummary {
  id: number;
  kind: "weekly" | "on_demand";
  period_start: string;
  period_end: string;
  sha256: string;
  signed: boolean;
  key_id: string | null;
  created_at: string;
}

type SeverityCounts = Record<"critical" | "high" | "medium" | "low" | "unknown", number>;

/** `scrutineering.report/v1`: posture, deployments and top images describe `generated_at`; the rest, the period. */
export interface ReportDocument {
  schema: string;
  kind: ReportSummary["kind"];
  period: { start: string; end: string; generated_at: string };
  posture: { active_images: number; running_images: number; open: SeverityCounts; fixable: number };
  changes: { new: SeverityCounts; resolved: SeverityCounts; reopened: SeverityCounts };
  scans: { by_status: Record<string, number>; images_not_scanned: number };
  remediations: {
    id: number;
    image: string | null;
    outcome: "completed" | "failed";
    targets: number;
    completed_at: string | null;
    evidence_sha256: string | null;
  }[];
  deployments: {
    containers: number;
    stale_containers: { container: string; image: string | null }[];
    fixes_not_running: {
      remediation_id: number;
      image: string | null;
      containers: number;
      fixed: number;
      not_fixed: string[];
    }[];
  };
  top_images: { image_id: number; image: string; critical: number; high: number }[];
}

export interface ReportDetail extends ReportSummary {
  document: ReportDocument;
}

/** A requested compliance export; the zip is downloadable for 24 hours once `ready`. */
export interface ComplianceExport {
  id: number;
  since: string;
  until: string;
  status: "pending" | "building" | "ready" | "failed";
  error: string | null;
  files: number | null;
  size: number | null;
  sha256: string | null;
  requested_by: string | null;
  created_at: string;
  finished_at: string | null;
}
