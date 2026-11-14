# Helm installation and upgrades

The supported packaged Kubernetes install is the chart in
`charts/scrutineering`. It runs the planner, authenticated Python API,
dashboard, Celery worker/Beat, and—by default—single-replica PostgreSQL and
Redis with persistent claims. Use an external database or Redis by disabling
the bundled component and supplying their URLs in the secret values.

## First install

Create a values file outside the repository or pass values through your secret
manager. The chart intentionally refuses to render without explicit secrets:

```bash
helm lint charts/scrutineering \
  --set secrets.databaseUrl='postgresql://scrutineering:PASSWORD@scrutineering-postgres:5432/scrutineering' \
  --set secrets.postgresPassword='PASSWORD' \
  --set secrets.redisUrl='redis://scrutineering-redis:6379/0' \
  --set secrets.celeryBrokerUrl='redis://scrutineering-redis:6379/0' \
  --set secrets.pythonApiKey='LONG_RANDOM_API_KEY'

helm upgrade --install scrutineering charts/scrutineering \
  --namespace scrutineering --create-namespace --wait --timeout 10m \
  -f values-production.yaml
```

For an existing Kubernetes Secret, set `secrets.create=false` and
`secrets.existingSecret` to its name. It must contain `DATABASE_URL`,
`POSTGRES_PASSWORD` when PostgreSQL is bundled, `REDIS_URL`,
`CELERY_BROKER_URL`, and `PYTHON_API_KEY`; trusted-proxy deployments also need
`DASHBOARD_TRUSTED_PROXY_SECRET`.

## Access and lifecycle

With ingress disabled, use the chart-generated port-forward command or:

```bash
kubectl -n scrutineering port-forward svc/scrutineering-dashboard 3001:3001
helm history scrutineering -n scrutineering
helm rollback scrutineering REVISION -n scrutineering --wait
```

Enable `ingress.enabled` only when an ingress controller, hostname, and TLS
policy are available. Database migrations remain an explicit release step;
run them before promoting a chart upgrade and verify `/ready` afterward.
