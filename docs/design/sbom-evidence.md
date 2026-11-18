# Signed SBOMs and remediation evidence

Status: proposed · 2026-11-18 · Phase 6

## Problem

Scrutineering knows what's in each image and what it did to fix one, but it can't
hand either over in a form anyone else can check:

- **No SBOM.** The scanners read every package in an image, but only the
  vulnerable ones are kept. "Which images contain `openssl 3.0.7`?" or "give me
  this image's component list" have no answer.
- **No evidence a reviewer can keep.** A remediation's story is spread across
  scans, the patch, the candidate's verification, the test run, the pull request,
  events and the rescan. The audit export proves operator actions, not "this fix
  removed CVE-X from this image, and here's the proof".
- **Nothing is signed.** An exported file can't be checked later for whether
  Scrutineering produced it, or whether someone changed it since.

## Scope

**In:**

- A **CycloneDX SBOM for every completed or partial image scan**, stored with
  the scan and downloadable.
- An **evidence bundle for every remediation** that reaches `completed` or
  `failed`: one JSON document, frozen when it's built.
- **Signatures** over each SBOM and bundle, with a **local key** that
  Scrutineering generates. Anyone can verify them with the public key, using
  `cosign verify-blob` or `openssl`, offline.
- **Downloads** in the dashboard: the SBOM on the scan and image pages, the
  evidence bundle on the remediation page, and the public key.

**Out:**

- Registry attestations (`cosign attest` onto the image). Decision 2 keeps
  SBOMs in the database only.
- Keyless signing (Sigstore, Fulcio, Rekor). Decision 1 chose a local key.
- SBOM search ("which images contain package X"). It's a natural next step
  once the data is there, but it needs its own UI and indexes.
- SPDX. CycloneDX only, which Trivy, Grype and most consumers read.
- Filesystem (`fs:`) scans. They aren't images and have no SBOM.

## Design

### SBOMs

After a scan completes (or ends `partial`) and before it's marked finished, the
worker runs Trivy once more on the **same target**, the digest when one was
resolved:

```
trivy image --format cyclonedx --cache-dir <same cache> <repo>@sha256:...
```

- **No second download.** Trivy reuses the layers it analysed a moment earlier
  from its cache, so this costs seconds, not another pull.
- **A failure doesn't fail the scan.** If the SBOM step fails or times out, the
  scan still succeeds. The scan's event detail records `sbom: failed`, and the
  error is logged.
- **Stored** in a new **`sboms`** table, one row per scan:

  | Column | Notes |
  |---|---|
  | `scan_id` | FK to `scans`, unique |
  | `format` | `cyclonedx-json` |
  | `spec_version` | read from the document, e.g. `1.6` |
  | `components` | count, for display |
  | `document` | the SBOM, as Trivy wrote it (`Text`) |
  | `sha256` | of `document` |
  | `signature`, `key_id` | added in step 2 |
  | `created_at` | |

- **Size:** a typical image's CycloneDX document is 0.2–3 MB. Every completed
  scan keeps its SBOM, as each scan keeps its observations. See Open questions
  on retention.

### Evidence bundles

When a remediation reaches `completed` or `failed`, the transition, through
`RemediationRepository.update_status` like notifications, records that a bundle
is due. A worker task then builds it on the `notify` queue, which is light and
never waits behind builds.

The bundle is canonical JSON (sorted keys, no whitespace):

```json
{
  "schema": "scrutineering.evidence/v1",
  "generated_at": "2026-11-18T09:00:00Z",
  "remediation": { "id": 57, "status": "completed", "image": "registry:5000/shop/api:1.4.2",
                   "approved_by": "alice", "created_at": "…", "completed_at": "…" },
  "targets": [ { "cve_id": "CVE-2021-23337", "package": "lodash", "from": "4.17.20", "severity": "high" } ],
  "plan": [ { "strategy": "dependency_update", "package": "lodash", "from": "4.17.20", "to": "4.17.21" } ],
  "patch": { "source_commit": "3fa…", "sha256": "…", "diff": "…" },
  "candidate": { "image": "…:scrutineering-candidate-57", "digest": "sha256:…",
                 "test_command": ["npm", "test"], "verification": { "still_present": [], "new_critical_or_high": [] } },
  "publication": { "provider": "github", "url": "https://github.com/shop/api/pull/9", "merged_at": "…" },
  "scans": {
    "before": { "scan_id": "…", "digest": "sha256:…", "sbom_sha256": "…", "open_findings": 412 },
    "after":  { "scan_id": "…", "digest": "sha256:…", "sbom_sha256": "…", "targets_present": [] }
  },
  "events": [ { "sequence": 1, "type": "approved", "at": "…", "detail": {} } ]
}
```

- Every fact comes from the server's own records (project rule 4). The SBOM
  hashes tie the bundle to the signed SBOMs without copying them in.
- It's stored in an **`evidence_bundles`** table, one per remediation: the
  document, `sha256`, signature and key ID. It's built once and never rebuilt. A
  retry (`failed` → `proposed`) that later ends again gets a new bundle, with
  the old one kept and the newest shown.

### Signing (local key)

- **The key:** an ECDSA P-256 key pair. The worker generates it on first use,
  with the `cryptography` package (a new, pinned Python dependency), at
  `/var/lib/scrutineering/signing/` on a new **`signingkeys`** volume. The
  private key file is mode `0600`, only the worker mounts the volume, and the
  private key never leaves the worker.
- **The public key** is written to a **`signing_keys`** table: key ID
  (`sha256:` of the DER public key), PEM, and `created_at`. The API serves it,
  so the API never needs the volume.
- **The signature** is ECDSA over SHA-256 of the exact stored bytes, base64. This
  is the format `cosign sign-blob` produces, so both of these work without any
  Scrutineering code:

  ```bash
  cosign verify-blob --key scrutineering.pub --signature sbom.sig --insecure-ignore-tlog sbom.json
  openssl dgst -sha256 -verify scrutineering.pub -signature <(base64 -d sbom.sig) sbom.json
  ```

  There's no cosign binary in the worker image, and none is needed.
- **Rotation:** delete the private key file and restart the worker. A new key is
  generated, and old public keys stay in `signing_keys`, so old signatures still
  verify. Each SBOM and bundle records its `key_id`.
- **SBOMs from before signing existed** stay unsigned. The download says so;
  nothing is signed retroactively.

### API and dashboard

| Method | Path | Role | Returns |
|---|---|---|---|
| GET | `/scans/{scan_id}/sbom` | any | The CycloneDX document, with its signature and key ID in headers |
| GET | `/scans/{scan_id}/sbom.sig` | any | The base64 signature |
| GET | `/images/{id}/sbom` | any | Redirect to the latest completed scan's SBOM |
| GET | `/remediations/{id}/evidence` | remediator | The bundle, with its signature and key ID in headers |
| GET | `/remediations/{id}/evidence.sig` | remediator | The base64 signature |
| GET | `/signing-keys` | any | Every public key: ID, PEM, created |

- **Scan and image pages:** "SBOM (CycloneDX) · N components", plus the
  signature.
- **Remediation page:** an "Evidence" panel once the bundle exists, with
  download buttons and the verification command.
- The operator guide gains a short "Verifying exports" section.

## Configuration

No new settings: SBOMs and evidence are always produced, and the key is
generated on first use.

| Change | Where |
|---|---|
| `signingkeys` volume, mounted only on the worker | Compose; k8s: a PVC on the worker |
| `cryptography` (pinned) | `requirements.txt` |

## Security

- **The private key** lives only on the worker's volume, `0600`, and isn't
  logged, served, or included in backups that the API makes. Whoever controls
  the worker can sign; that's the same trust boundary as the scans themselves.
  The signature proves "this Scrutineering instance produced it", not that a
  person reviewed it.
- **Signatures cover the exact stored bytes,** so a downloaded file verifies
  only if it's unchanged.
- **No client-supplied content** is signed: SBOMs come from Trivy on the server,
  and bundles from server records (rule 4).
- **What the SBOM reveals:** an SBOM lists every component of an image. The
  read routes need a signed-in user, as the findings do (#136/#137 in trusted-
  proxy mode). The bundle includes the patch, so it needs the remediator role,
  like the remediation page.

## Testing

- **Unit tests:**
  - the SBOM step: the command, the target, storing the document, and a failure
    not failing the scan;
  - key generation, idempotency and permissions;
  - signing, with verification by the `cryptography` public key and by `openssl`
    against a fixed vector;
  - the bundle builder: every field from records, canonical bytes, built once,
    and a retry giving a new bundle;
  - the routes' roles and headers.
- **Golden path:** after the loop completes, the remediation has an evidence
  bundle whose signature verifies against `/signing-keys`, and whose `before`
  and `after` scans name SBOMs that also verify. The recorded scanner output
  includes a CycloneDX fixture, so the fake `trivy` answers `--format cyclonedx`.
- **Live (`make e2e`):** download the e2e image's SBOM and the remediation's
  bundle through the dashboard, and verify both with `openssl` against the
  served public key.

## Rollout

1. **SBOMs:**
   - the SBOM step in the worker;
   - migration `0010` (`sboms`);
   - the scan and image routes and dashboard links;
   - tests, docs and the e2e download.
2. **Signing:**
   - `cryptography`;
   - the key volume, generation, and `signing_keys` (migration `0011`);
   - signing SBOMs;
   - `/signing-keys` and the `.sig` routes;
   - the "Verifying exports" guide section.
3. **Evidence bundles:**
   - the builder, with recording through `update_status`;
   - migration `0012` (`evidence_bundles`);
   - the remediation route and panel;
   - golden-path and e2e verification.

Each step keeps the golden path green.

## Decisions

Decided before the note was written (2026-11-18):

1. **Signing:** a local key, generated by Scrutineering. No internet, accounts,
   or public transparency log.
2. **Storage:** in the database, downloadable from the dashboard. No registry
   attestations.

## Open questions

1. **Retention.** SBOMs add 0.2–3 MB per completed scan. With discovery and
   6-hourly rescans, that grows.
   *Recommendation:* keep the SBOM of the latest completed scan per image, plus
   any SBOM an evidence bundle refers to. Prune the rest daily in the beat
   sweep, with no setting.
2. **cosign compatibility.** Should the public key and signatures follow
   cosign's conventions exactly (PEM public key, base64 signature) so
   `cosign verify-blob` works, at the cost of a slightly unusual `.sig`?
   *Recommendation:* yes. It's the most widely used verifier, and `openssl`
   still works.
3. **Who can download SBOMs.** Any signed-in role, as findings, or the operator
   role and above?
   *Recommendation:* any role. An SBOM reveals less than the findings, which
   every role already sees.
