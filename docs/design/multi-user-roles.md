# Multi-user roles

Status: proposed · 2026-11-20 · Phase 6

## Problem

Forward-auth (`forward-auth.md`) lets several people sign in, and maps their groups onto
five roles. But the roles were written for one operator, and with more than one person
three things go wrong:

- **One person can ship a fix alone.** `security-operator` and `admin` pass every
  remediator check. So the same person can propose a fix, approve it, accept its new
  findings and publish it. Approval exists to put a second pair of eyes on a change
  that ends up as a pull request, and today nothing enforces that.
- **The remediation doesn't say who did what.** Only `approved_by` is stored. Who
  proposed, executed, accepted and published a fix is in the audit log, so the
  dashboard can't show it and the server can't check it.
- **Nobody can review access.** Who has signed in, with which roles, is only known to
  the identity provider. Findings are assigned to free text, which may not be a
  person who can act on them. And what each role may do is spread over about 30
  `require_role` calls.

## Scope

**In:**

- **One role matrix in code**, `src/api/roles.py`: action → roles. Every route checks an
  action, not a list of roles. `/permissions` and the operator guide are generated from
  the same table.
- **Who did what, on the remediation:** `proposed_by`, `executed_by`, `accepted_by`
  and `published_by` columns, next to `approved_by`. Each is set by the route that
  makes the change, from the signed-in identity, never from the request body.
- **Separation of duties:** with `REMEDIATION_SEPARATE_APPROVER` on, the person who
  proposed a fix can't approve it, and can't accept its new critical or high findings.
  The API refuses with `403 separate_approver_required` and says why. Admins are bound
  by it too.
- **People:** a `principals` table records each signed-in identity, with its email,
  its roles at last sign-in, and when it was last seen. The record is written at most
  once an hour per person. An admin-only **People** page lists them, for access
  reviews. Findings are assigned to a principal from that list, not free text.

**Out:**

- **User management.** The identity provider owns accounts, groups and passwords.
  Scrutineering records what it's told; it never grants a role.
- **Custom roles and per-image permissions.** The five roles stay.
- **Per-user API tokens.** Scripts keep the API key, as in `forward-auth.md`.
- **Separate approval for publishing.** Publishing an approved, verified fix is the
  same person's call; the check is on approval.

## Design

### The role matrix

```python
ACTIONS = {
    "scans.manage":           {"operator", "security-operator"},
    "findings.triage":        {"operator", "security-operator"},
    "remediations.view":      {"remediator", "security-operator"},
    "remediations.propose":   {"remediator", "security-operator"},
    "remediations.execute":   {"remediator", "security-operator"},
    "remediations.approve":   {"security-operator"},
    "remediations.accept":    {"security-operator"},
    "remediations.publish":   {"security-operator"},
    "remediations.retry":     {"security-operator"},
    "remediations.cancel":    {"remediator", "security-operator"},
    "sources.manage":         {"remediator", "security-operator"},
    "audit.export":           {"security-operator"},
    "compliance.export":      {"security-operator"},
    "notifications.manage":   {"security-operator"},
    "reports.build":          set(),          # admin only
    "people.view":            set(),          # admin only
}
```

`admin` passes every action. `require_action(request, "remediations.approve")` replaces
`require_role(...)`. A test fails if a route under `/api/dashboard` that changes state
checks no action. The matrix above is today's behaviour, unchanged. Moving it into one
place is the first step; changing it is a separate decision (open question 2).

### Separation of duties

With `REMEDIATION_SEPARATE_APPROVER=on`:

- **Approve** (`proposed` → `approved`) is refused when the caller is `proposed_by`.
- **Accept** (`needs_acceptance` → `ready`) is refused when the caller is
  `proposed_by`.
- **Retry** (`failed` → `proposed`) sets `proposed_by` to the caller, so a retry needs
  a fresh approval from someone else.

People are compared by their identity-provider subject (`principal_id`), not their
email. In `local` mode every request is the same API-key identity, so the check can't
mean anything there. `auto`, the default, turns it on in `trusted-proxy` mode and
off in `local` mode. `on` with `local` mode fails at startup.

Remediations created before the migration have no `proposed_by`, so the check passes
for them.

### Data

Migration 0016:

- `remediations` gains `proposed_by`, `executed_by`, `accepted_by` and `published_by`,
  each a nullable `String(128)`.
- `principals`: `id`, `subject` (unique), `email`, `roles` (JSON list),
  `first_seen_at`, `last_seen_at`.
- `scan_findings.assigned_to` keeps its column. The API checks that a new value is a
  known principal's subject.

Principals not seen for 365 days are deleted by a daily sweep. Their subject stays
in the audit log, which is history.

### API and dashboard

| Method | Path | Action | |
|---|---|---|---|
| GET | `/permissions` | any | Gains `actions`: the caller's allowed actions, from the matrix |
| GET | `/people` | `people.view` | Principals: subject, email, roles, first and last seen |
| — | `/remediations/{id}` | — | Gains `proposed_by`, `executed_by`, `accepted_by`, `published_by` |

The remediation page shows who did each step. When separation is on and the viewer
proposed the fix, the Approve and Accept buttons are disabled with "Someone else has
to approve this". The finding assignment control picks from known people.

## Configuration

| Variable | Default | Services | |
|---|---|---|---|
| `REMEDIATION_SEPARATE_APPROVER` | `auto` | api | `auto`, `on` or `off`; `auto` is on in `trusted-proxy` mode |

## Security

- **Identity comes from the proxy only.** `proposed_by` and the others come from
  `request.state.principal_id`, never from a request body (project rule 4).
- **Separation is checked on the server.** A disabled button is a convenience; the
  API refuses.
- **What's stored about people:** subject, email and roles, which the dashboard
  already shows in the header. The People page needs `admin`, and the sweep deletes
  people not seen for a year.
- **What it doesn't stop:** one person with two accounts, or an identity provider that
  puts everyone in the security group. Those are the provider's to control; the People
  page makes them visible.

## Testing

- **Unit tests:**
  - every route that changes state checks an action;
  - the matrix gives today's behaviour, role by role;
  - each actor column is set by its route and never from a body;
  - separation refuses self-approval and self-acceptance, binds admins, and is reset by
    a retry;
  - `auto` in each auth mode, and `on` with `local` refused at startup;
  - principals are recorded once an hour at most, and pruned after a year;
  - assignment accepts only known principals.
- **Golden path:** runs in `local` mode, where `auto` is off, so it's unchanged.
- **Live:** the forward-auth example stack with two Authelia users. One proposes, the
  approval as the same user gets a 403, and the other user approves.

## Rollout

1. **Role matrix:** `src/api/roles.py`, every route on `require_action`, `/permissions`
   gains `actions`, and the generated role table in the guide. No behaviour change.
2. **Actors and separation:** migration 0016's remediation columns, the routes that set
   them, `REMEDIATION_SEPARATE_APPROVER`, and the remediation page.
3. **People:** the `principals` table and sweep, `/people`, the People page, and
   assignment from known people.

## Open questions

1. **Default for separation of duties.** `auto` (on with sign-in, off with the API
   key), or off until an operator turns it on?
   *Recommendation:* `auto`. Several people signing in is when it matters, and a
   single-user forward-auth setup can set `off`.
2. **Should `security-operator` keep the remediator actions?** Today a security
   operator can also propose and execute. Removing that makes the split structural,
   but a small team would need two groups per person.
   *Recommendation:* keep them, and rely on separation of duties. It stops
   self-approval without making small teams juggle groups.
3. **Recording principals.** Keep a `principals` table, or derive People from the audit
   log?
   *Recommendation:* the table. The audit log records actions, not sign-ins, so someone
   who only reads would never appear. The table is also the only way to show their
   current roles. It holds one row per person and is pruned after a year.
