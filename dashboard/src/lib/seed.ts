// Seed data for development — in production replace with real API calls
import { PostureSummary, ScanResult, ImageDetail, VulnerabilityFinding, SeverityTrend } from '../types';

const IMAGES: ImageDetail[] = [
  { id: 1, registry: 'dockerhub', repo_name: 'library/nginx', tag: '1.25', last_scan_at: '2025-04-04T12:30:00Z', last_scan_id: 'scan-101', open_findings: 14, critical_count: 1, high_count: 5, medium_count: 6, low_count: 2 },
  { id: 2, registry: 'dockerhub', repo_name: 'library/redis', tag: '7-alpine', last_scan_at: '2025-04-04T11:00:00Z', last_scan_id: 'scan-102', open_findings: 7, critical_count: 0, high_count: 2, medium_count: 3, low_count: 2 },
  { id: 3, registry: 'ghcr.io', repo_name: 'myorg/api-gateway', tag: 'v2.3.1', last_scan_at: '2025-04-04T10:15:00Z', last_scan_id: 'scan-103', open_findings: 3, critical_count: 1, high_count: 1, medium_count: 1, low_count: 0 },
  { id: 4, registry: 'gcr.io', repo_name: 'my-project/worker', tag: 'latest', last_scan_at: '2025-04-03T22:00:00Z', last_scan_id: 'scan-104', open_findings: 22, critical_count: 3, high_count: 9, medium_count: 7, low_count: 3 },
  { id: 5, registry: 'dockerhub', repo_name: 'library/postgres', tag: '16', last_scan_at: '2025-04-03T20:45:00Z', last_scan_id: 'scan-105', open_findings: 2, critical_count: 0, high_count: 1, medium_count: 1, low_count: 0 },
];

const FINDINGS: VulnerabilityFinding[] = [
  { id: 1, fingerprint: 'aaa', cve_id: 'CVE-2024-0727', package_name: 'openssl', package_version: '3.0.12', package_type: 'apk', severity: 'CRITICAL', title: 'Use-after-free in X.509 name checks', description: 'A critical flaw in OpenSSL X.509 verification.', fixed_version: '3.0.13', fix_available: true, first_seen: '2025-03-01T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 2, fingerprint: 'bbb', cve_id: 'CVE-2023-5678', package_name: 'libcurl', package_version: '7.88.1', package_type: 'apk', severity: 'HIGH', title: 'HTTP/2 header injection', description: 'Header injection via malformed HTTP/2 requests.', fixed_version: '8.1.0', fix_available: true, first_seen: '2025-03-05T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 3, fingerprint: 'ccc', cve_id: 'CVE-2023-4442', package_name: 'busybox', package_version: '1.35.0', package_type: 'apk', severity: 'MEDIUM', title: 'Buffer over-read in unzip', description: 'Read past end of buffer when extracting archives.', fixed_version: null, fix_available: false, first_seen: '2025-02-20T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 4, fingerprint: 'ddd', cve_id: 'CVE-2024-1234', package_name: 'zlib', package_version: '1.2.13', package_type: 'apk', severity: 'LOW', title: 'Memory leak in deflate', description: 'Minor memory leak in deflateInit2.', fixed_version: '1.3.0', fix_available: true, first_seen: '2025-01-15T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 5, fingerprint: 'eee', cve_id: 'CVE-2023-7890', package_name: 'busybox', package_version: '1.35.0', package_type: 'apk', severity: 'HIGH', title: 'Stack overflow in awk', description: 'Stack-based overflow in awk builtin.', fixed_version: '1.36.0', fix_available: true, first_seen: '2025-02-10T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 6, fingerprint: 'fff', cve_id: 'CVE-2024-5678', package_name: 'busybox', package_version: '1.35.0', package_type: 'apk', severity: 'HIGH', title: 'Use-after-free in udhcpc', description: 'Heap corruption in DHCP client.', fixed_version: null, fix_available: false, first_seen: '2025-03-15T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 7, fingerprint: 'ggg', cve_id: 'CVE-2024-9012', package_name: 'musl', package_version: '1.2.5', package_type: 'apk', severity: 'MEDIUM', title: 'Buffer overflow in realpath', description: 'Off-by-one in realpath function.', fixed_version: '1.2.6', fix_available: true, first_seen: '2025-03-20T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 8, fingerprint: 'hhh', cve_id: 'CVE-2023-3390', package_name: 'libtasn1', package_version: '4.16.0', package_type: 'apk', severity: 'HIGH', title: 'Integer overflow in ASN.1 parser', description: 'Overflow in integer parsing.', fixed_version: '4.17.0', fix_available: true, first_seen: '2025-01-28T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 9, fingerprint: 'iii', cve_id: 'CVE-2024-7777', package_name: 'busybox', package_version: '1.35.0', package_type: 'apk', severity: 'CRITICAL', title: 'Heap overflow in httpd', description: 'Critical heap overflow in busybox httpd.', fixed_version: '1.36.1', fix_available: true, first_seen: '2025-04-01T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 10, fingerprint: 'jjj', cve_id: 'CVE-2024-1111', package_name: 'expat', package_version: '2.5.0', package_type: 'apk', severity: 'HIGH', title: 'Billion laughs attack', description: 'XML entity expansion DoS.', fixed_version: '2.6.0', fix_available: true, first_seen: '2025-02-15T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 11, fingerprint: 'kkk', cve_id: 'CVE-2023-2222', package_name: 'libxml2', package_version: '2.10.3', package_type: 'apk', severity: 'MEDIUM', title: 'Null pointer deref in XML parser', description: null, fixed_version: '2.11.0', fix_available: true, first_seen: '2025-01-10T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 12, fingerprint: 'lll', cve_id: 'CVE-2024-3333', package_name: 'libunistring', package_version: '1.0', package_type: 'apk', severity: 'HIGH', title: 'Integer overflow in string functions', description: 'Integer overflow in Unicode string normalization.', fixed_version: '1.1', fix_available: true, first_seen: '2025-03-01T00:00:00Z', last_seen: '2025-04-04T12:30:00Z', remediated: false },
  { id: 13, fingerprint: 'mmm', cve_id: 'CVE-2024-4444', package_name: 'busybox', package_version: '1.35.0', package_type: 'apk', severity: 'CRITICAL', title: 'Auth bypass in telnetd', description: 'Authentication bypass in busybox telnet daemon.', fixed_version: null, fix_available: false, first_seen: '2025-04-02T00:00:00Z', last_seen: '2025-04-03T22:00:00Z', remediated: false },
  { id: 14, fingerprint: 'nnn', cve_id: 'CVE-2023-5555', package_name: 'linux-headers', package_version: '6.1.0', package_type: 'apk', severity: 'HIGH', title: 'Privilege escalation via mmap', description: 'Local privilege escalation via crafted mmap.', fixed_version: '6.1.100', fix_available: true, first_seen: '2025-01-05T00:00:00Z', last_seen: '2025-04-03T22:00:00Z', remediated: false },
];

const SCANS: ScanResult[] = [
  { scan_id: 'scan-105', image_name: 'library/postgres:16', status: 'completed', started_at: '2025-04-03T20:40:00Z', completed_at: '2025-04-03T20:45:00Z', findings: 2, critical_count: 0, high_count: 1, medium_count: 1, low_count: 0 },
  { scan_id: 'scan-104', image_name: 'my-project/worker:latest', status: 'completed', started_at: '2025-04-03T21:50:00Z', completed_at: '2025-04-03T22:00:00Z', findings: 22, critical_count: 3, high_count: 9, medium_count: 7, low_count: 3 },
  { scan_id: 'scan-103', image_name: 'myorg/api-gateway:v2.3.1', status: 'completed', started_at: '2025-04-04T10:10:00Z', completed_at: '2025-04-04T10:15:00Z', findings: 3, critical_count: 1, high_count: 1, medium_count: 1, low_count: 0 },
  { scan_id: 'scan-102', image_name: 'library/redis:7-alpine', status: 'completed', started_at: '2025-04-04T10:55:00Z', completed_at: '2025-04-04T11:00:00Z', findings: 7, critical_count: 0, high_count: 2, medium_count: 3, low_count: 2 },
  { scan_id: 'scan-101', image_name: 'library/nginx:1.25', status: 'completed', started_at: '2025-04-04T12:25:00Z', completed_at: '2025-04-04T12:30:00Z', findings: 14, critical_count: 1, high_count: 5, medium_count: 6, low_count: 2 },
];

const TRENDS: SeverityTrend[] = [
  { date: '2025-03-05', critical: 4, high: 12, medium: 15, low: 5 },
  { date: '2025-03-10', critical: 5, high: 14, medium: 12, low: 4 },
  { date: '2025-03-15', critical: 3, high: 11, medium: 13, low: 6 },
  { date: '2025-03-20', critical: 4, high: 13, medium: 14, low: 5 },
  { date: '2025-03-25', critical: 2, high: 10, medium: 11, low: 4 },
  { date: '2025-03-30', critical: 3, high: 11, medium: 10, low: 3 },
  { date: '2025-04-04', critical: 5, high: 18, medium: 14, low: 7 },
];

export function getPostureSummary(): PostureSummary {
  const totalFindings = FINDINGS.length;
  const fixable = FINDINGS.filter(f => f.fix_available).length;
  const lastScan = SCANS[SCANS.length - 1];
  return {
    total_scanned_images: IMAGES.length,
    total_findings: totalFindings,
    critical_count: FINDINGS.filter(f => f.severity === 'CRITICAL').length,
    high_count: FINDINGS.filter(f => f.severity === 'HIGH').length,
    medium_count: FINDINGS.filter(f => f.severity === 'MEDIUM').length,
    low_count: FINDINGS.filter(f => f.severity === 'LOW').length,
    fixable_count: fixable,
    last_scan_at: lastScan?.completed_at || null,
    last_scan_status: lastScan?.status || null,
  };
}

export function getSeverityTrend(days = 30): SeverityTrend[] {
  return TRENDS;
}

export function getScanHistory(limit = 20): ScanResult[] {
  return SCANS.slice(0, limit);
}

export function getImages(): ImageDetail[] {
  return IMAGES;
}

export function getImageById(id: string): ImageDetail | undefined {
  return IMAGES.find(i => i.id === parseInt(id));
}

export function getFindingsByImage(imageId: string, severity?: string): VulnerabilityFinding[] {
  let findings = [...FINDINGS];
  if (severity && severity !== 'all') {
    findings = findings.filter(f => f.severity === severity);
  }
  return findings;
}
