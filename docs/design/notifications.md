# Notifications (Slack and webhook)

Status: in progress, steps 1 and 2 of 3 built (outbox, webhook, Slack) · 2026-11-17 · Phase 6

## Problem

Remediation pauses until a person acts on it. A proposed fix waits for approval,
a candidate with new critical findings waits for acceptance, and a verified fix
waits to be published. Today the only way to find these is to open the
dashboard. The outcomes (a PR opened, a fix completed, a build failed) are
silent too.

## Scope

**In:**

- A message when a remediation reaches a state where a person must act, or a
  final state:

  | Status | Why it matters | Who acts |
  |---|---|---|
  | `proposed` | a fix is waiting for approval | security operator |
  | `needs_acceptance` | the candidate fixed its targets but added critical/high findings | security operator |
  | `ready` | verified; publish it, or rebuild the image | remediator |
  | `published` | the pull request is open (link included) | the repository's reviewers |
  | `completed` | a complete rescan no longer shows the targets | nobody |
  | `failed` | the reason, shortened | remediator |

- Two channels, each optional:
  - a **Slack incoming webhook**;
  - a **generic webhook**: signed JSON, for ntfy, n8n, Home Assistant, a chat
    bridge, or your own code.
- A **test** button in the dashboard that sends a sample message to each
  configured channel and shows the result.

**Out**, for now:

- Email, PagerDuty, Microsoft Teams. The generic webhook covers them through a
  bridge.
- Routing rules: per-image channels, severity filters, quiet hours.
  `NOTIFICATION_EVENTS` is the only filter.
- Channels configured from the browser. URLs come only from the environment
  (see Security).
- Alerts for new critical findings found by scans (see Decisions).
- Digests and scheduled reports, which are a separate Phase 6 item.

`approved`, `building`, `verifying` and `cancelled` are left out on purpose. A
person caused them, or they pass within minutes, so they're noise in a channel.

## Design

### Where messages come from

Every remediation status change goes through
`RemediationRepository.update_status` (`src/db/repositories.py`). The worker,
the lifecycle checks, publication, the webhook and the dashboard routes all
call it.

When the target status is in `NOTIFICATION_EVENTS` and at least one channel is
configured, `update_status` also inserts one row per channel into a new
**`notifications`** table, in the same transaction. This is an outbox:

- A status change that rolls back sends nothing.
- A change that commits always gets its message, even if the worker restarts
  before delivering it.

Creating a remediation is the one status change that doesn't go through
`update_status`: the create route sets `proposed` itself. That route therefore
records the `proposed` message too, after the planned actions exist so the message
can name the action. No other code creates notifications, so a new call site
that changes the status can't forget to send one.

### The `notifications` table (migration 0008)

| Column | Notes |
|---|---|
| `id` | also the delivery ID that receivers use to drop duplicates |
| `channel` | `slack` or `webhook` |
| `event` | e.g. `remediation.needs_acceptance` |
| `remediation_id` | nullable FK, `ON DELETE SET NULL` |
| `payload` | JSON, built when the row is written, so a message describes the remediation at the moment of the change |
| `status` | `pending` → `sent`, or `pending` → `failed` after the last attempt |
| `attempts`, `last_error`, `next_attempt_at`, `created_at`, `sent_at` | |

`status` is the delivery's own state. A remediation's state is never read from
this table (project rule 3).

### Delivery

- `src/notifications/` is a new top-level module, which this note authorizes.
  It holds the payload builder, one formatter per channel, and a Celery task,
  `deliver_pending`.
- `deliver_pending` runs:
  - right after the transaction that wrote a row commits (an `after_commit`
    hook enqueues it);
  - every minute from beat, as a sweep, so a lost enqueue only delays a message.
- It runs on a new queue, **`notify`**. With prefetch 1, putting it on
  `remediation.normal` or `scan.*` would leave messages waiting behind
  multi-minute builds and scans. `notify` is added to the default
  `CELERY_QUEUES`, Compose, and the k8s ConfigMap.
- It claims due rows with `SELECT … FOR UPDATE SKIP LOCKED`, so two workers
  never send the same row. It then posts with `httpx`:
  - 10-second timeout;
  - no redirects;
  - any 2xx counts as sent.
- On failure, retries come at 1, 5, 15 and 60 minutes. The fifth failure marks
  the row `failed`. `last_error` holds the status code, or the exception class
  and message, never the URL.
- Delivery is **at least once**: a crash between the post and the update can
  repeat a message. The webhook carries the delivery ID so receivers can
  de-duplicate. Slack can't, and an occasional repeat is acceptable there.

### Payload

The generic webhook receives this JSON. Slack receives the same facts as a
short message: a headline, the image, counts, and a link button.

```json
{
  "id": 412,
  "event": "remediation.needs_acceptance",
  "occurred_at": "2026-11-17T14:03:11Z",
  "remediation": {
    "id": 57,
    "status": "needs_acceptance",
    "label": "Needs acceptance: new findings",
    "image": "registry.local/shop/api:1.4.2",
    "action": "base_image_bump",
    "targets": 3,
    "new_critical_high": ["CVE-2026-1234"],
    "pull_request_url": null,
    "error": null,
    "url": "https://scrutineering.home.lan/remediations/57"
  }
}
```

- `url` is present only when `DASHBOARD_PUBLIC_URL` is set.
- `error` is the first line of the remediation's `error_message`, cut to 300
  characters. Build output can contain anything a build step printed, so the
  rest stays in the dashboard.
- Payloads never include source code, environment values or tokens.

### Dashboard

- A new **Notifications** page (`/notifications`), linked from the menu. For
  each channel it shows:
  - whether the channel is configured (yes or no, never the URL);
  - the last 20 deliveries, with their status and error;
  - **Send test**.
- The page is backed by two routes, both requiring `security-operator`:
  - `GET /api/dashboard/notifications`;
  - `POST /api/dashboard/notifications/test`.
- A test row goes through the same outbox, with event `test`, and the panel
  polls until it's sent or failed. The test therefore exercises the real
  delivery path.

## Configuration

All settings are in `src/config.py`, so they appear in `CONFIGURATION.md`, and
all are optional. With no channel URL set, the feature is off and the outbox
stays empty.

| Variable | Default | Used by | Notes |
|---|---|---|---|
| `NOTIFICATION_SLACK_WEBHOOK_URL` | empty | api, worker | Secret. Must be `https://hooks.slack.com/…`. |
| `NOTIFICATION_WEBHOOK_URL` | empty | api, worker | Secret. `https://`, or `http://` on the LAN (decision 2). |
| `NOTIFICATION_WEBHOOK_SECRET` | empty | api, worker | Secret. Signs each body; required with the webhook URL. |
| `NOTIFICATION_EVENTS` | the six in Scope | api, worker | Comma list of statuses; unknown ones fail at startup. |
| `DASHBOARD_PUBLIC_URL` | empty | api, worker | Base URL for links in messages; links are omitted when empty. |

The API and the worker both call `update_status`, so both need
`NOTIFICATION_EVENTS` and must know which channels are set. The API is
therefore given the channel variables too (Compose and the k8s Secret already
share them between services), but it only checks whether they're empty. Only
the worker sends anything.

## Security

- **The URLs are credentials.** A Slack incoming-webhook URL lets anyone post to
  the channel. All three values are `SecretStr`, never logged or returned by the
  API, and absent from `last_error`.
- **No SSRF from the browser.** Destinations come only from the environment.
  Nobody with dashboard access can point the worker at an internal address.
- **Signing.** Each webhook request carries:
  - `X-Scrutineering-Signature: sha256=<HMAC-SHA256 of the raw body with NOTIFICATION_WEBHOOK_SECRET>`,
    the same scheme as GitHub's;
  - `X-Scrutineering-Delivery: <id>`;
  - `X-Scrutineering-Event`.

  The operator guide includes a receiver snippet that verifies the signature
  with a constant-time compare.
- **What an attacker gains** by reading the messages: image names, CVE IDs,
  remediation states and PR links. That's sensitive for a security tool, so the
  operator guide says to send messages only to private channels.
- **Kubernetes:** the worker's NetworkPolicy already allows egress on 443, and
  the API needs no new egress. Plain-HTTP targets would need a policy change.

## Testing

- **Unit tests:**
  - `update_status` writes outbox rows only for configured events and channels,
    and writes none when the transaction rolls back;
  - the payload builder, including the error shortening and the URL;
  - the webhook request, with a signature test vector;
  - retry scheduling, the final `failed` status, and errors that never contain
    the URL;
  - every new setting is validated.

  `SELECT … FOR UPDATE SKIP LOCKED` is a no-op on the SQLite test database.
  Step 1 checked it by hand on the Compose stack's Postgres; there are no
  Postgres tests in CI.
- **Golden path:** the test points `NOTIFICATION_WEBHOOK_URL` at an in-process
  receiver and asserts:
  - one signed delivery for each event in the loop (`proposed`, `ready`,
    `published`, `completed`), in order;
  - that each body's `remediation.status` matches the remediation's status at
    that point.

  `make e2e` doesn't check notifications yet: the live stack would need a
  receiver the worker container can reach, and `.env` changes. That's left for
  step 3, whose test button gives a live check through the dashboard.
- No test sends anything to Slack. The Slack formatter is checked against the
  stored JSON in `fixtures/notifications/`.

## Rollout

1. **Outbox and webhook** (built):
   - migration 0008;
   - recording in `update_status`;
   - the settings;
   - `src/notifications/` with the webhook channel;
   - the `notify` queue, the beat sweep, and the golden-path assertions;
   - docs: OPERATOR_GUIDE section, ARCHITECTURE (services and data model),
     CONFIGURATION.
2. **Slack** (built): the formatter, the URL check, and docs.
3. **Dashboard:** the Notifications page, the two routes and the test button.

Each PR keeps the golden path green and leaves the feature off when nothing is
configured. This note is updated to match what shipped.

## Decisions

These were open questions on the proposal; all four were decided as recommended.

1. **Scan alerts:** a later step, after these three. It will cover critical
   findings only, with at most one message per image per scan.
2. **Plain HTTP:** allowed only to a private address (RFC 1918, loopback or
   link-local) or a single-label host name. Anything else must be `https://`.
3. **`ready`:** stays in the default events while publication is a manual step.
4. **Retention:** the sweep deletes `sent` rows older than 30 days and keeps
   `failed` rows. There's no setting for this.
