# GitHub and Cloudflare Staging Callback Setup

This guide configures a temporary GitHub publication/callback test against a
local Scrutineering stack. It does not make the local machine directly
reachable: `cloudflared` creates an outbound tunnel and Cloudflare supplies an
HTTPS URL.

## Prerequisites

- Docker Compose is running and `curl http://localhost:8000/health` returns
  `{"status":"ok"}`.
- You control `pespringer/scrutineering` and its `main` branch is protected.
- If the repository is private under a personal GitHub Free account, GitHub
  may reject branch-protection API requests; upgrade the account or use a
  public/dedicated staging repository before testing publication.
- The webhook endpoint can be reached through a public HTTPS URL. A Quick
  Tunnel is suitable for one test; use a named tunnel for a stable hostname.

## Configure `.env`

Create a short-lived, fine-grained GitHub token at GitHub **Settings →
Developer settings → Personal access tokens → Fine-grained tokens**. Select
only `pespringer/scrutineering`, set **Metadata: read** and **Pull requests:
read/write**, **Administration: read**, and give it a short expiration. The
publisher checks branch
protection and creates a pull request; it does not merge one.

The publisher intentionally fails closed when it cannot verify branch
protection. A token with **Administration: read** is necessary but not
sufficient if the repository’s GitHub plan does not support protected branches.

Generate a separate webhook secret locally:

```bash
openssl rand -hex 32
vim .env
```

Set these values, without committing or sharing them:

```dotenv
GITHUB_TOKEN=<fine-grained-token>
GITHUB_WEBHOOK_SECRET=<random-hex-secret>
REMEDIATION_ALLOWED_REPOSITORIES=pespringer/scrutineering
REMEDIATION_PUBLICATION_ENABLED=true
```

Keep `.env` ignored by Git. Disable publication and revoke the token when the
test is complete.

## Start a temporary Cloudflare Quick Tunnel

Install `cloudflared`, then run this in a separate terminal:

```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

Copy the printed `https://<random>.trycloudflare.com` URL. Keep the process
running; the URL changes when the process is restarted. Quick Tunnels are for
development/testing, not production traffic.

For a stable hostname, create a named Cloudflare Tunnel, add a published
application route to `http://127.0.0.1:8000`, and run the tunnel using its
account-provided token. Do not expose PostgreSQL, Redis, or the dashboard
unless separately required.

## Configure the GitHub webhook

Open the repository’s **Settings → Webhooks → Add webhook** and set:

| Setting | Value |
| --- | --- |
| Payload URL | `https://<tunnel-host>/api/dashboard/webhooks/github` |
| Content type | `application/json` |
| Secret | The exact `GITHUB_WEBHOOK_SECRET` value |
| Events | **Pull requests** only |
| Active | Enabled |

GitHub sends the HMAC in `X-Hub-Signature-256`. Do not enable insecure SSL
verification. Use the webhook’s **Recent Deliveries → Redeliver** control only
after confirming the original delivery ID is not already recorded; duplicate
IDs are intentionally ignored.

## Verify the setup

From the repository root:

```bash
docker compose up -d
docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade heads
curl http://localhost:8000/health
npm run smoke:dashboard
npm run drill:staging-provider
```

The provider webhook path is the one deliberate exception to the internal API
key boundary: it is not accepted with `PYTHON_API_KEY`; it must pass the
provider-specific HMAC check and delivery-ID replay check. All other API and
dashboard routes retain their normal API-key, service-auth, or trusted OIDC
requirements.

Then use GitHub’s webhook **Test delivery** or create one controlled staging
pull request. Confirm the delivery is successful, the callback appears in the
remediation timeline, and reconciliation reports the publication state.

## Cleanup

Set `REMEDIATION_PUBLICATION_ENABLED=false`, stop `cloudflared`, delete the
GitHub webhook, revoke the fine-grained token, rotate the webhook secret, and
retain the publication/callback/verification evidence for the staging record.
