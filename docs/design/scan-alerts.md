# Scan alerts

Status: accepted · 2026-11-27 · Phase 6 · step 1 built

## Problem

Notifications cover remediations, out-of-date containers and the weekly report.
Scans are silent. When a scheduled rescan finds a new critical CVE in a running
image, nobody hears about it until someone opens the dashboard or reads the next
weekly report. A scan that starts failing is silent too. For example, the image's
registry may be unreachable or its credentials expired. The image then simply
stops being checked, and nothing says so.

[notifications.md](notifications.md) left this for a later step (decision 1):
critical findings only, at most one message per image per scan.

## Scope

**In:**

- **`new_critical`:** a scan found critical findings that weren't open and
  critical on that image before it. One message per scan, naming the image and the
  new CVEs.
- **`scan_failed`:** a scan that no person started failed, and the image's previous
  scan didn't. One message when an image starts failing, not one per failed scan.
- Both go through the existing outbox, channels, retries and Notifications page,
  and are chosen with `NOTIFICATION_EVENTS`.

**Out:**

- **High, medium and low findings.** A busy image gains new highs every week, so
  they belong in the weekly report. A severity setting can come later if critical
  alone proves too narrow (see Decisions).
- **A message when an image recovers,** or when a critical finding is resolved.
  The dashboard shows both, and `completed` covers fixes.
- **Partial scans as failures.** One scanner failed but the other's findings were
  saved, so new criticals are still reported. The scan list marks them.
- **Per-image routing, quiet hours and digests.** As for remediation messages,
  `NOTIFICATION_EVENTS` is the only filter.
- **Candidate scans.** Remediation verification scans candidates without saving
  findings, so they never alert. Their result is in the `ready`,
  `needs_acceptance` or `failed` message.

## Design

### `new_critical`

**The rule.** Count the critical findings this scan observed whose CVE and package
(`vuln_key`) had no open critical finding on the image before the scan. That covers:

- a finding seen for the first time;
- a finding that was resolved and is back (a fix that regressed);
- an open finding whose severity was raised to critical. Scanner databases do
  revise severities.

The package version is left out on purpose. An upgrade that doesn't fix the CVE
creates a new finding row (rows are keyed by version too), but it isn't news. The
golden path's own fixture does this: the rebuilt image's `tar` moves from 6.1.11 to
6.2.1 and keeps CVE-2026-59873, and `node` moves to 18.20.8 and keeps CVE-2026-111497.

**Where.** `persist_findings` (`src/scan/utils/db.py`) already holds every finding
row of the image in one transaction, before and after the scan's changes. It
works out the new critical findings there and calls a new
`outbox.record_new_critical`, which writes the rows in that same transaction. It
writes nothing when there are none, when no channel is configured, or when
`new_critical` isn't in `NOTIFICATION_EVENTS`. Saving findings and queueing the
alert therefore commit or roll back together, as remediation messages do.

**Every scan counts,** whoever started it: scheduled, discovery, after a merge,
manual or retried. A manual scan's result is on screen for the person who ran it,
but the channel may be read by someone else.

**The first scan of an image counts too.** All its critical findings are new, so
it sends one message. That's deliberate. A new tag of an existing app (`app:1.5`
after `app:1.4`) is a new image to Scrutineering, and staying silent would hide
the criticals it introduced. Turning on runtime discovery for a host with many
images can send one message per image once, which the operator guide says (see
Decisions).

### `scan_failed`

**The rule.** When a scan moves to `failed`, queue a message if:

- it wasn't started by a person, so its trigger is `scheduled`, `discovery` or
  `post_merge`. A person who started a scan sees it fail in the dashboard;
- and the image's previous finished scan (`completed`, `partial` or `failed`)
  wasn't `failed`, or there was none.

An image that fails every 6 hours while its registry is down sends one message.
The next one comes after a scan of it has succeeded and then failed again.

**Where.** Every failure goes through `mark_scan_failed` (`src/scan/records.py`),
which calls a new `outbox.record_scan_failed` in the same transaction. A scan
cancelled first is never marked failed, so it never alerts.

### Payloads

The generic webhook receives:

```json
{
  "id": 913,
  "event": "scan.new_critical",
  "occurred_at": "2026-11-27T06:00:41Z",
  "scan": {
    "id": "c1f0…",
    "image": "registry:5000/shop/api:1.4.2",
    "trigger": "scheduled",
    "status": "completed",
    "url": "https://scrutineering.home.lan/scans/c1f0…"
  },
  "findings": {
    "new_critical": 3,
    "open_critical": 7,
    "fixable": 2,
    "cve_count": 3,
    "cves": ["CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333"],
    "url": "https://scrutineering.home.lan/images/42"
  }
}
```

- `cves` lists distinct CVE IDs, at most 20, sorted. `cve_count` is how many there
  are, so a message can say how many weren't listed. Findings without a CVE ID are
  counted in `new_critical`, but not listed.
- `fixable` is how many of the new ones have a fixed version, so whether a
  remediation can be proposed.
- The URLs are present only when `DASHBOARD_PUBLIC_URL` is set.

`scan.failed` carries the same `scan` object and an `error`: the first line of the
scan's `error_message`, cut to 300 characters, as for remediation errors. Scanner
errors can include registry responses, so the rest stays in the dashboard.

Slack gets a short message from the same facts:

- for `scan.new_critical`: a headline ("3 new critical findings in
  `registry:5000/shop/api:1.4.2`"), the first five CVEs, the counts, and buttons to
  the scan and the image;
- for `scan.failed`: the image, the trigger, the error and a button to the scan.

Values written by others (image names, errors) are escaped as for the existing
messages.

### Delivery and the dashboard

Nothing changes:

- The rows go to the `notifications` table with `remediation_id` empty, like
  `report.ready`.
- The `notify` queue, the retries and retention, and the Notifications page,
  which lists recent deliveries and the configured events, cover them as they are.
- The page's **Send test** stays a generic sample.

## Configuration

**No new variables.** `NOTIFICATION_EVENTS` accepts `new_critical` and
`scan_failed`, and both join its default list.

**Upgrading:**

- An installation on the default list starts receiving both events.
- One that set `NOTIFICATION_EVENTS` itself receives neither until it adds them.

`docs/CONFIGURATION.md` and the operator guide say so.

## Security

- **Same channels and secrets** as the existing messages, so no new trust
  boundary and no new egress.
- **What a reader learns:** which images have which unpatched critical CVEs. For a
  security tool that's the most sensitive message it sends, and a ready list of
  targets. The operator guide's advice to use private channels is repeated in the
  new section.
- **Untrusted text:** image names come from whoever pushed or started the
  container, and error text from registries and scanners. Both are cut to size.
  Slack gets them escaped, and the webhook gets them as JSON strings.
- **Flooding:** one message per image per scan at most, and failures only when an
  image starts failing. A burst is limited by the number of images, as with
  remediation messages.

## Testing

- **Unit tests, `new_critical`:**
  - a first scan, a new finding, a reopened finding, a severity raised to critical;
  - an upgraded package with the same critical CVE (no message);
  - a finding already open and critical (no message);
  - a high finding (no message);
  - a partial scan;
  - one message for several findings of the same CVE;
  - the 20-CVE cap;
  - nothing queued when the findings' transaction rolls back, when no channel is
    configured, or when the event is turned off.
- **Unit tests, `scan_failed`:**
  - each trigger;
  - the first failure after a success, a repeated failure, and the first scan
    failing;
  - a cancelled scan;
  - errors cut to their first line.
- **Unit tests, formatting:**
  - Slack messages for both, checked against stored JSON in
    `fixtures/notifications/`;
  - the configuration's accepted events.
- **Golden path:** the in-process receiver gets:
  - in the loop test, one `scan.new_critical` for the fixture's first scan (12 CVEs
    from Trivy and Grype, including CVE-2026-59873 in `tar`), then the four
    remediation messages in order. The rescans add none;
  - in the rescan test, one for the first scan and one for the rebuilt image, listing
    only CVE-2026-4738 (`zlib`) and CVE-2026-63073 (`libcrypto3`, `libssl3`). The
    CVEs that `tar` and `node` kept through their upgrades aren't listed again.
- **Live:** `make e2e` keeps skipping notification delivery when no channel is
  configured. Before merging, each event is checked by hand against a local
  webhook receiver:
  - a scheduled scan that finds a new critical;
  - a scheduled scan of an image whose registry is stopped, failing twice, with one
    message.

## Rollout

One PR per step:

1. **`new_critical`:** the rule in `persist_findings`, the payload, Slack, the
   event, golden-path assertions and docs (operator guide, `CONFIGURATION.md`).
2. **`scan_failed`:** the rule in `mark_scan_failed`, the payload, Slack, the
   event and docs.

Each step leaves notifications unchanged when no channel is configured.

## Decisions

These were open questions on the proposal; all four were decided as recommended.

1. **First scans** alert too, so a new tag's criticals aren't hidden.
2. **Critical only,** as notifications.md decided. A setting that also allows high
   would be a new environment variable, and can come later.
3. **Failed scans** alert only when no person started them.
4. **Both events are on by default,** as the existing events are.
