# Deployment Evidence Collection

The signed callback and GitHub Actions workflow are a compatibility path, not
the preferred operator experience. The long-term workflow must keep evidence
collection inside Scrutineering and avoid requiring users to copy values between
GitHub, a deployment system, and the dashboard.

## Target operator flow

1. A remediation publication records the immutable artifact digest it produced.
2. Scrutineering discovers the configured deployment target from the
   publication's environment and repository configuration.
3. A provider adapter resolves the currently running image digest and rollout
   state directly from that target.
4. The API associates the observation with the publication, runs the existing
   scan/finding policy, and updates the timeline automatically.
5. The dashboard shows collection progress, the source used, the observed
   digest, and the final verification or rollback decision.

Manual digest entry and signed callbacks remain available for unsupported
platforms, but they must be clearly marked as operator-supplied evidence and
must not be required for normal operation.

## Adapter boundary

Deployment collectors should implement one provider-neutral contract with
bounded timeouts, redacted diagnostics, and explicit unavailable states. The
first adapters should target local Docker/Compose and Kubernetes; later
adapters can cover ECS, Nomad, and generic HTTPS health/deployment APIs.
Adapters must return the resolved image digest, rollout status, source identity,
observation timestamp, and an evidence fingerprint. Mutable tags, guessed
digests, and unverified user input fail closed.

The GitHub Actions workflow in `.github/workflows/deployment-evidence.yml`
remains useful for environments Scrutineering cannot reach, but it is a
fallback integration and not a prerequisite for local or connected deployments.

## Current configuration boundary

Automatic collection is selected by repository with
`DEPLOYMENT_COLLECTOR_TARGETS_JSON`:

```dotenv
DEPLOYMENT_COLLECTOR_TARGETS_JSON={"acme/api":{"provider":"kubernetes","namespace":"security","selector":"app=api"},"local/api":{"provider":"docker","container":"api"}}
```

Operators request collection through the dashboard/API action
`POST /api/dashboard/remediations/publications/{id}/collect-deployment-observation`.
The worker returns a task ID while the runtime observation and reconciliation
are persisted asynchronously. Runtime command access is intentionally a
deployment decision: Docker collection requires access to the Docker runtime,
and Kubernetes collection requires a scoped `kubectl` context or service
account; neither is silently enabled by the API container.

For local Docker collection, rebuild the worker and opt into the dedicated
overlay only on a host where the worker is trusted to inspect the Docker
Engine:

```bash
export DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
docker compose -f docker-compose.yml -f docker-compose.deployment-docker.yml up --build -d celery-worker
```

The default Compose stack does not mount `/var/run/docker.sock`. Kubernetes
deployments should apply `k8s/deployment-observation-rbac.yaml` and configure
the worker target selector in `DEPLOYMENT_COLLECTOR_TARGETS_JSON`; the role is
limited to reading pod status and does not permit workload mutation. When the
worker runs in Kubernetes, the collector uses the standard service-account
token and CA mount together with `KUBERNETES_SERVICE_HOST`; outside the cluster,
`kubectl` uses its normal kubeconfig/context. Do not broaden the role to permit
deployments, pods, or other workload mutation.
