# Compliance Reports

Security operators can generate durable compliance reports from the current
PostgreSQL posture and audit trail. Supported frameworks are NIST SP 800-190,
PCI DSS 4.0, SOC 2 Type II, HIPAA Security Rule, and GDPR Article 32.

Reports are stored in `compliance_reports` with the framework scope, summary,
format, generation timestamp, and actor. JSON reports retain the structured
control results. Markdown reports additionally retain a human-readable
evidence document in the report record.

Use the dashboard **Compliance** page or the authenticated API:

```bash
curl http://localhost:3001/api/compliance/reports
curl -X POST http://localhost:3001/api/compliance/reports \
  -H 'content-type: application/json' \
  -d '{"framework":"soc2","output_format":"markdown"}'
```

Generation is restricted to `security-operator` and `admin`. The report is an
evidence snapshot; it does not claim that deferred provider publication,
deployment observation, or external alert delivery has been validated.
