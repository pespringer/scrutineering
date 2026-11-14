# Policy Engine

Scrutineering evaluates enabled policies whenever a completed scan persists
findings. Results are stored as `PolicyEvaluation` records and remain tied to
the scan and policy that produced them.

## Supported policies

- `severity_threshold` compares observed critical/high/medium/low/unknown
  counts with bounded `max_*` rules.
- `image_allowlist` requires the exact scanned image reference to appear in
  `rules.images`.
- `image_denylist` violates when the exact scanned image reference appears in
  `rules.images`.

Actions (`block`, `alert`, `require_approval`, and the other policy actions)
are recorded with the violation. A policy decision does not silently merge or
remediate anything; provider publication and automatic external notification
remain separately gated.

Security operators can create, pause, and review policies from the **Policies**
dashboard page. Read-only users can inspect active policies and evaluation
counts. Policy changes and manual re-evaluations are audit events.

The authenticated API is also available for automation:

```bash
curl http://localhost:3001/api/policies
curl -X POST http://localhost:3001/api/policies \
  -H 'content-type: application/json' \
  -d '{"name":"Release gate","policy_type":"severity_threshold","action":"block","rules":{"max_critical":0,"max_high":5}}'
```

Policies fail closed on malformed rules and require `security-operator` or
`admin` for mutation.
