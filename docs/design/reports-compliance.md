# Scheduled reports and compliance export

Status: built · 2026-11-20 · Phase 6

## Problem

Scrutineering knows, at any moment, what is open, what was fixed and how, and what
still runs an old build. But the only way to see it is to open the dashboard and
look around, and there's no way to hand it to someone else:

- **Nobody is told how the week went.** New criticals, fixes completed and stale
  containers only show up if someone checks. Notifications cover single
  remediations, not the overall picture.
- **There's no record over time.** The posture page shows "now" and a severity
  trend, but not "what was true last Monday".
- **Proof is scattered.** An auditor (or future you) asking "what did you fix in
  Q3, and how do you know?" gets evidence bundles one remediation at a time, SBOMs
  one scan at a time, and the audit log through an API call. Nothing ties them into
  one package whose integrity can be checked.

## Scope

**In:**

- **A weekly report**, built by the worker on a schedule: posture now, what
  changed in the week, completed and failed fixes, and stale containers. It's
  stored, signed like an SBOM, readable as a dashboard page, and downloadable as
  JSON.
- **A notification** when a report is ready (`report_ready`), through the
  existing channels. The message has a short summary and a link to the page.
- **A compliance export:** one zip for a date range. It holds the evidence bundles,
  the SBOMs they cite, the reports, a findings CSV, the audit log, and the public
  keys, plus a **signed manifest** that lists every file's SHA-256.

**Out:**

- **Email.** No mail channel exists. Reports reach people through Slack or the
  webhook (which can feed an email gateway), or the dashboard.
- **PDF.** A browser prints the report page well enough. A PDF renderer is a large
  dependency for little gain.
- **Custom report contents, or more than one schedule.** One weekly report, the
  same for everyone.
- **Storing the export.** It's built on request and kept for 24 hours to download,
  because its contents already live in the database.
- **Framework mappings** (SOC 2, ISO 27001 control IDs). The export holds the
  facts; mapping them to controls is the auditor's job.

## Design

### The weekly report

**Period.** The 7 whole days (UTC) before the run, from Monday 00:00 to Monday
00:00. A weekly report is identified by its period start, so a second run for the
same week does nothing. A report built on demand (kind `on_demand`) covers this
week so far, from Monday 00:00 to the moment it's built, and never replaces the
weekly one.

**Contents** (`scrutineering.report/v1`, canonical JSON as for evidence), from
server records only:

| Section | What |
|---|---|
| `period` | start, end, generated at |
| `posture` | active images, running images, open findings by severity, fixable |
| `changes` | findings first seen, resolved and reopened in the period, by severity |
| `scans` | scans in the period by status, and images not scanned in the period |
| `remediations` | completed and failed in the period: ID, image, targets, outcome, evidence SHA-256 |
| `deployments` | completed fixes with containers still on an older build, and every stale container now |
| `top_images` | the 10 images with the most open critical and high findings |

**Signing.** The worker signs the report with the instance key (`src/signing.py`),
like SBOMs and evidence. If the key can't be used, the report is stored unsigned.

**Rendering.** The dashboard page `/reports/{id}` renders the stored JSON. No HTML is
stored: one source of truth, and nothing for a renderer to get wrong at build time.
"Print" gives a usable paper copy.

**Data: the `reports` table** (migration 0014): `id`, `kind` (`weekly` or
`on_demand`), `period_start`, `period_end`, `document`, `sha256`, `signature`,
`key_id`, `created_at`, unique on (`kind`, `period_start`, `period_end`). Reports are a few kilobytes and
are kept indefinitely.

**Schedule.** A beat entry on `REPORT_SCHEDULE_CRON` (default `0 7 * * 1`, Monday
07:00 UTC) queues the build on `scan.low`. `off` disables it. Beat runs in UTC.

**Notification.** After a report is stored, a `report_ready` notification is queued
to each configured channel. It's a new value for `NOTIFICATION_EVENTS`, on by
default. The payload holds the period, open critical and high counts and their
change, fixes completed, stale containers, and the page URL. The report itself
isn't attached, so Slack never holds more than a summary.

### The compliance export

**Request, build, download.** Only the worker holds the signing key, so the export is
a job:

1. `POST /compliance/exports {since, until}` (security-operator) records the request
   and queues the build on `scan.low`.
2. The worker builds the zip, signs its manifest, and stores the zip in the
   `compliance_exports` table (migration 0015) with its size and SHA-256.
3. The page polls `GET /compliance/exports/{id}`, then downloads
   `GET /compliance/exports/{id}/download`.

An hourly sweep deletes exports older than 24 hours, and fails a request no worker
finished within an hour. The range is at most 366 days, and a zip over 512 MB fails.
If the signing key can't be used, the export fails: an unsigned manifest proves
nothing. The manifest is deterministic for the same records; the signature isn't,
because ECDSA signatures are randomized. In `findings.csv`, a cell starting with
`=`, `+`, `-` or `@` gets a leading `'`, so a spreadsheet doesn't run scanner text as
a formula.

**Contents:**

```text
scrutineering-export-2026-07-01_2026-09-30.zip
├── manifest.json                 every file below: path, SHA-256, size; range; key ID
├── manifest.json.sig             base64 signature over manifest.json
├── keys/<fingerprint>.pem        every public key that signed something in the zip
├── evidence/<remediation>-<bundle>.json(.sig)    bundles that ended in the range
├── sboms/<scan id>.cdx.json(.sig)                SBOMs those bundles cite
├── reports/<period start>.json(.sig)             weekly reports in the range
├── findings.csv                  findings open at export time, plus those resolved in the range
└── audit.json                    audit records in the range, with their hash chain
```

Files keep their own signatures, so each can be verified on its own as well. The
signed manifest covers the files that have none (`findings.csv`, `audit.json`) and
the zip as a whole. Verifying the manifest with `openssl`, then checking each
`sha256sum`, proves nothing was added, removed or changed.

### API and dashboard

| Method | Path | Role | |
|---|---|---|---|
| GET | `/reports` | any | List, newest first |
| GET | `/reports/{id}` | any | The report's JSON, with `sha256`, `signed`, `key_id` |
| GET | `/reports/{id}.sig` | any | Its signature |
| POST | `/reports` | admin | Build an on-demand report for this week so far |
| POST | `/compliance/exports` | security-operator | `{since, until}`; 202 with the export ID |
| GET | `/compliance/exports` | security-operator | Recent exports and their state |
| GET | `/compliance/exports/{id}/download` | security-operator | The zip |

The dashboard gains a **Reports** page (list, each report rendered, and a **Build
report now** button for admins). It also
gains a **Compliance export** form on the same page for security operators.

## Configuration

| Variable | Default | Services | |
|---|---|---|---|
| `REPORT_SCHEDULE_CRON` | `0 7 * * 1` | beat | Five cron fields (UTC), or `off` |

`NOTIFICATION_EVENTS` gains `report_ready` in its default.

## Security

- **Signing stays on the worker.** The API never sees the key. Every signed thing
  (SBOM, evidence, report, export manifest) is built and signed by the worker from
  its own records.
- **Who sees what.**
  - Reports hold what the dashboard already shows, so any signed-in role can read
    them.
  - The export holds evidence bundles, which include patches, and the audit log. It
    needs `security-operator`, the role that already exports the audit log.
- **Size.** The 366-day cap and one running export at a time keep a request from
  filling the database. A second request while one is building is refused.
- **What leaves.** The Slack and webhook messages carry counts and a link, never the
  report's contents or any finding detail.

## Testing

- **Unit tests:**
  - the report's period boundaries, and that each week is built only once;
  - each section from fixed records, including empty weeks;
  - canonical bytes and the signature;
  - the notification payload;
  - the manifest lists every file with the right SHA-256, and its signature
    verifies with `openssl`;
  - range limits, the role checks, one export at a time, and the 24-hour sweep.
- **Golden path:** unchanged.
- **Live (`make e2e`):** after the remediation, build a report for the current
  week and check it lists the completed fix and verifies. Then request an export
  for today, unzip it, verify the manifest with `openssl`, and check each file
  against `sha256sum`.

## Rollout

1. **Weekly report:** migration 0014, the builder, the schedule, the routes, the
   Reports page, `report_ready`, tests and the e2e check.
2. **Compliance export:** migration 0015, the worker job, the routes, the export
   form, the sweep, tests and the e2e check.

Each step keeps the golden path green.

## Decisions

Decided 2026-11-20 (the recommendations accepted with the overnight plan):

1. **Weekly, Monday 07:00 UTC,** with `REPORT_SCHEDULE_CRON` to change it.
2. **Reports are stored in the database** and shown in the dashboard. The existing
   channels post a link; there's no email channel.
3. **The export is a zip with a signed `manifest.json`** listing every file's SHA-256.

## Open questions

1. **Timezone.** The schedule and the week boundaries are UTC.
   *Recommendation:* keep UTC. A `TZ` setting means two clocks to reason about,
   and Monday 07:00 UTC is Monday morning across Europe and early Monday in the
   Americas.
2. **What `findings.csv` covers.** Findings open at export time, plus those
   resolved in the range, or only the range?
   *Recommendation:* both. An auditor wants what's open now and what was fixed in
   the period.
3. **Who can build a report on demand.**
   *Recommendation:* `admin` only. Reports are signed and kept forever, so they
   shouldn't be cheap to make.
