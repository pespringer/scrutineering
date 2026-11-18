# Scrutineering

Scrutineering finds vulnerabilities in container images and fixes them.

1. It scans each image with Trivy and Grype and tracks every finding across scans.
2. For findings with a known fix, it patches the image's source (dependency updates,
   OS package upgrades, base-image bumps).
3. It builds the patched image and scans it to prove the fix works.
4. It opens a GitHub pull request with the change.
5. When the rebuilt image scans clean, it marks the fix completed.

Nothing is applied without an operator's approval, and every verdict comes from
Scrutineering's own scans.

## Quick start

You need Docker with Compose, `openssl`, and `make`. Ports 3001, 5000 and 8000 must
be free.

```bash
git clone https://github.com/pespringer/scrutineering.git && cd scrutineering
cp .env.example .env

# Generate the database password and API key, and set them in .env.
PW=$(openssl rand -hex 16) KEY=$(openssl rand -hex 32)
sed -i.bak -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$PW|" \
  -e "s|^DATABASE_URL=.*|DATABASE_URL=postgresql+psycopg2://scrutineering:$PW@postgres:5432/scrutineering|" \
  -e "s|^PYTHON_API_KEY=.*|PYTHON_API_KEY=$KEY|" .env && rm .env.bak

make up        # build and start the stack (docker compose up --build -d)
make migrate   # create the database schema
make smoke     # check that the API and dashboard answer
```

Open the dashboard at <http://localhost:3001>.

## Scan your first image

The stack includes a local registry. Push to it from your machine as
`localhost:5000`; Scrutineering reaches it as `registry:5000`:

```bash
docker build -t localhost:5000/demo/vulnerable-node:1.0 fixtures/images/vulnerable-node
docker push localhost:5000/demo/vulnerable-node:1.0
```

In the dashboard, open **Images → Registry catalog** and choose **Scan image** next
to `demo/vulnerable-node:1.0`. The first scan downloads the vulnerability
databases, so it takes a few minutes; later scans are quicker. When it finishes,
open the image to see its findings. One of them is CVE-2021-23337 in lodash, which
has a fix.

To fix it, connect the image to its source, propose and approve the fix, and let
Scrutineering build and verify it. The [operator guide](docs/OPERATOR_GUIDE.md)
walks through each step. Building fixes needs `REMEDIATION_EXECUTION_ENABLED=true`
in `.env`, and opening pull requests needs `GITHUB_TOKEN`.

## How it fits together

The services are:
- the dashboard (Next.js);
- the API (FastAPI);
- a Celery worker that runs the scanners and builds fixes on rootless BuildKit;
- Celery beat for scheduled rescans;
- Postgres, Redis, and the local registry.

[ARCHITECTURE.md](docs/ARCHITECTURE.md) has the diagram, the data model, and the
state machines.

## Documentation

- [Operator guide](docs/OPERATOR_GUIDE.md): scan, triage, fix and verify, plus
  troubleshooting.
- [Architecture](docs/ARCHITECTURE.md): services, the loop, data model, state
  machines and trust boundaries.
- [Configuration](docs/CONFIGURATION.md): every setting, generated from
  `src/config.py`.
- [Dashboard API](docs/api/dashboard-v1.md): every route and the role it needs.
- [Remediation execution](docs/operations/remediation-execution.md) and
  [GitHub publication](docs/operations/github-publication.md): fixes in detail.
- [Documentation index](docs/README.md), the [reset plan](docs/RESET-PLAN.md), and
  [design notes](docs/design/) for planned work.

## Development

Development needs Python 3.12 with [uv](https://docs.astral.sh/uv/), Node.js 20, and
Docker.

```bash
make test         # Python tests and repository checks
make e2e          # the golden path against the running stack, with real scanners
make fmt          # format with Ruff and Prettier
make fmt-check    # formatting, lint, and the 120-character line limit (as in CI)
cd dashboard && npm ci && npm run dev   # the dashboard with live reload
```

The golden-path test (`tests/e2e/test_golden_path.py`) defines "working": a change
that breaks it does not merge. Repository conventions are in
[AGENTS.md](AGENTS.md). CI (`.github/workflows/ci.yml`) runs the tests, the
repository checks, the format check and the dashboard build on every pull request.
On `main` it also builds the images and scans the API image with Trivy.

## Deploying to Kubernetes

The manifests in `k8s/` run the API, dashboard, worker, beat, Postgres, Redis and a
registry for remediation candidates in the `scrutineering` namespace. Rootless BuildKit
runs in its own namespace, `scrutineering-buildkit`, because it needs unconfined
seccomp and AppArmor, which the main namespace's `restricted` Pod Security level forbids.

1. Set the real secrets in `k8s/infrastructure.yaml` (or replace that Secret with
   your own). `POSTGRES_PASSWORD` must match the password in `DATABASE_URL`.
2. Create the namespace, apply the rest, then BuildKit:

   ```bash
   kubectl apply -f k8s/pod-security.yaml
   kubectl apply -n scrutineering -f k8s/
   kubectl apply -f k8s/buildkit/
   ```

3. Run the migrations:

   ```bash
   kubectl exec -n scrutineering deploy/scrutineering-api -- \
     alembic -c src/db/migrations/alembic.ini upgrade head
   ```

To build fixes, set `REMEDIATION_EXECUTION_ENABLED: "true"` in the ConfigMap. On
Kubernetes, sources must be `https://` repositories, since there is no local sources
folder. The manifests are checked offline (`tests/test_k8s_manifests.py`: Pod Security,
quota, services, network policies) but have not yet been applied to a cluster. Keep
`PYTHON_API_KEY` in the Secret. If an ingress verifies users, see
[dashboard operations](docs/operations/dashboard.md) for the trusted-proxy setup.
