# Clearer scan errors

Status: accepted · 2026-11-27 · Phase 6 · built

## Problem

When a scan fails, its error rarely says why. With the registry stopped, a scan of
`registry:5000/fixtures/vulnerable-node:fail-test` recorded:

```text
all configured scanners failed: [trivy] Failed to parse JSON output: Expecting value:
line 1 column 1 (char 0); [grype] Exit code 1:
```

(one line, wrapped here)

The scan page shows that line, and since [scan-alerts.md](scan-alerts.md) so does the
`scan_failed` alert. Neither tells the operator that the registry is down, that its
credentials were refused, or that the tag doesn't exist. Yet both scanners printed exactly
that, and the worker's own registry check knew it before they started. Two bugs, and a
missing step, lose it:

- **Trivy's exit code is misread.** `src/scan/scanners/trivy.py` accepts exit code 1
  because "Trivy returns 1 when findings exist". It doesn't: without `--exit-code`,
  Trivy exits 0 with findings and 1 on a fatal error. Checked with Trivy 0.76.2: 0 for
  the golden-path fixture (with findings), 1 for each failure below. So a failed Trivy
  run is parsed as JSON, its empty output fails to parse, and its stderr is dropped.
- **Grype's errors are silenced.** It runs with `-q`, which in Grype 0.121.2 suppresses
  its error output too, so stderr is empty and the error is just `Exit code 1:`.
- **Nothing says why in plain words.** Before scanning, `_resolve_scan_target` asks the
  registry for the tag's digest. When that fails it logs a warning and scans by tag
  anyway, and the reason the registry gave, with its HTTP status, goes nowhere the
  operator looks.

What the scanners actually print, captured from the worker image:

| Cause | Trivy (`remote error:` line) | Grype (`oci-registry:` line) |
| --- | --- | --- |
| Registry down | `dial tcp …:5999: connect: connection refused` | the same |
| No such tag | `MANIFEST_UNKNOWN: manifest unknown; unknown tag=no-such-tag` | the same |
| Private or missing Docker Hub repository | `UNAUTHORIZED: authentication required` | the same |
| Unanswered host | still retrying after 2 minutes, then `connect: connection timed out` | nothing, with `-q` |

## Scope

**In:**

- Fix both scanner bugs, and keep the line of each scanner's stderr that names the cause.
- A plain first line in the failed scan's `error_message` that says what went wrong and
  what to check. Each scanner's own error follows on its own line.
- The same for a scan that fails because `REQUIRE_IMMUTABLE_SCAN_IDENTITY` is set and the
  digest can't be resolved, and for a remediation's candidate scan.
- The scan page keeps the lines apart.

**Out:**

- **Skipping the scanners** when the registry check has already failed. That would save
  time with an unreachable host, but the scanners have their own ways to fetch an image,
  and some registries answer a manifest `HEAD` differently from a pull. See Decisions.
- **Retries and backoff.** Failed scheduled scans are retried by the next schedule, as
  today.
- **A reason code** stored on the scan, or a new `reason` field in the webhook payload.
  See Decisions.
- **Partial scans.** One scanner's error is kept as today, but with the cleaned-up text.
  There's no plain first line, because the scan still saved findings.

## Design

### 1. The scanners' own errors

- **Trivy:** only exit code 0 is a success. On any other exit, the error is the
  `remote error:` line when there is one. Otherwise it's the last part of the `FATAL`
  line after `run error:`, and failing that the last non-empty line of stderr.
- **Grype:** drop `-q`. Without a terminal Grype writes no progress, so stderr holds
  only its log lines: two lines for the golden-path fixture. On a non-zero exit, the
  error is the `oci-registry:` line when there is one. Otherwise it's the
  first `ERROR` line, and failing that the last non-empty line. On success its warnings,
  such as "EOL distro", are ignored, as today.
- Each error is cut to 500 characters, as today. The full stderr isn't stored.
- Trivy's SBOM run, after a scan, reports a failure the same way (`SBOM failed: …`).

A run that exits 0 but prints no valid JSON still fails with "Failed to parse JSON
output".

### 2. A plain reason

A new `src/scan/failure.py` turns what is known into one sentence. The first source is
the digest lookup's exception, since it is structured: `HTTPError` with its status code,
`URLError` with its reason, `PermissionError` from the auth challenge. When the image was
given by digest, or the lookup succeeded, it uses the scanners' errors. Network phrases
are matched case-insensitively. Registry error codes (`MANIFEST_UNKNOWN`, `DENIED`, …) are
matched exactly, so a local "permission denied" isn't read as the registry's `DENIED`. A
registry cause counts only in an error that names the image's registry host. A scanner that
couldn't download its vulnerability database is therefore not reported as the registry being
down. A registry cause outranks a scanner timeout.

| Cause | Detected by | First line |
| --- | --- | --- |
| Can't connect | `connection refused`, `no such host`, `i/o timeout`, `connection timed out`, `URLError` | Couldn't reach the registry `{host}` ({detail}). Check that it's running and that the worker can reach it. |
| HTTP to an HTTPS client | `server gave HTTP response to HTTPS client` | `{host}` answers only over plain HTTP. Only the local registry may, with `REGISTRY_INSECURE=true`. |
| Untrusted certificate | `x509:` | `{host}`'s TLS certificate isn't trusted by the worker. |
| 401, no credentials for the host | `UNAUTHORIZED`, 401 | `{host}` refused to serve `{repository}` without credentials. It's private, or it doesn't exist. Add credentials (`REGISTRY_CREDENTIALS_JSON`, or `DOCKERHUB_USERNAME` for Docker Hub). |
| 401 or 403, with credentials | `UNAUTHORIZED`, `DENIED`, 401, 403 | `{host}` refused the configured credentials for `{repository}`, or the repository doesn't exist. |
| 404 | `MANIFEST_UNKNOWN`, `NAME_UNKNOWN`, 404 | `{reference}` isn't in the registry: no such tag or repository. |
| 429 | `TOOMANYREQUESTS`, 429 | `{host}` is limiting pulls. Try again later; Docker Hub allows more with `DOCKERHUB_USERNAME`. |
| Scanner timeout | the timeout error | The scanners didn't finish within `SCANNER_TIMEOUT` ({n} s). |
| Anything else | | The scanners failed. |

- Docker Hub answers 401 for a repository that doesn't exist, which is why that line
  says "or it doesn't exist".
- `{host}`, `{repository}` and `{reference}` come from the parsed image identity, not
  from the error text. `{detail}` is the matched phrase, such as "connection refused".
- When the sources disagree, the digest lookup wins, since it asked the registry
  directly. Each scanner's line still follows, so nothing is hidden.

The stored message becomes:

```text
Couldn't reach the registry registry:5000 (connection refused). Check that it's running and …
trivy: Get "http://registry:5000/v2/": dial tcp 172.19.0.5:5000: connect: connection refused
grype: failed to get image descriptor from registry: Get "http://registry:5000/v2/": dial tcp …
```

The `scan.failed` alert already sends the first line, so it now carries the reason with
no change to the alert. The scan page shows the message with its line breaks
(`whitespace-pre-line`), with the first line in bold.

### Where

- `_resolve_scan_target` keeps the lookup's exception, alongside the string it already
  records in the `scan_started` audit event.
- `_execute_scan`, when every scanner failed, builds the message through
  `failure.explain(identity, lookup_error, scanner_errors)`. The `identity_unresolved`
  path uses `failure.unresolved`: the reason, or "Couldn't resolve … to a digest", then a
  line saying `REQUIRE_IMMUTABLE_SCAN_IDENTITY` stopped it from scanning by tag.
- `inspect_image` gives the remediation worker the same message when no scanner could
  scan a candidate. A candidate is named by digest, so its reason comes from the
  scanners' text. When only one scanner failed, the remediation still fails, as today,
  with that scanner's cleaned-up line.

There's no migration. Older scans keep their messages.

## Configuration

None. The hints name the existing `REGISTRY_INSECURE`, `REGISTRY_CREDENTIALS_JSON`,
`DOCKERHUB_USERNAME` and `SCANNER_TIMEOUT`.

## Security

- **Untrusted text:** registry and scanner errors are written by whoever runs the
  registry. They're cut to size as today, and the reason's host and repository come from
  the image identity, not from the error. The dashboard renders the message as text, and
  Slack escapes it.
- **Secrets:** neither scanner prints the password it was given, and the digest lookup's
  errors carry the URL and status, not the request headers. The tests check that a
  configured password never appears in a stored message.
- **What it reveals:** the existence of a private repository is never confirmed, since a
  401 is worded as "private, or it doesn't exist". Messages go only to people who can
  already see the scan, and to the configured channels.

## Testing

- **Unit tests,** from stderr captured from Trivy 0.76.2 and Grype 0.121.2 and stored in
  `fixtures/scanner-errors/`, for each cause in the table:
  - the scanners: exit code 1 is a failure, and the right line is kept; exit 0 with
    findings and Grype's warnings still succeeds;
  - the reason: each row, from a lookup exception and from scanner text alone; the
    lookup winning a disagreement; an unknown error; and a message that never contains
    the configured password;
  - `REQUIRE_IMMUTABLE_SCAN_IDENTITY` and a candidate scan.
- **Golden path:** a scan of `registry:5000/fixtures/vulnerable-node:no-such-tag`, with
  the real scanners, fails with "isn't in the registry" as its first line.
- **Live, before merging:** a scan with the registry stopped, then one of a private
  Docker Hub repository, checked on the scan page.

## Rollout

One PR per step:

1. **The scanners' errors:** both bugs, the kept lines and their fixtures. On its own,
   this already turns the example above into the two "connection refused" lines.
2. **The plain reason:** `failure.py`, its use in the three paths, the scan page, the
   golden-path assertion, and the operator guide's troubleshooting section.

## Decisions

These were open questions on the proposal; all three were decided as recommended.

1. **The scanners always run,** even when the digest lookup can't connect or gets a 404.
   They stay the authority. Revisit if timeouts against unanswered hosts turn out to be
   common: each can cost up to `SCANNER_TIMEOUT` per scanner.
2. **No reason code is stored.** The first line serves the dashboard and alerts; a code
   would need a migration and an API change.
3. **Hints name settings,** as in the table, since each one names the setting that fixes it.
