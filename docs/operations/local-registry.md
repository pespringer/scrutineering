# Local Registry Operations

The default Docker Compose stack includes a private, unauthenticated OCI
registry for local testing. It avoids requiring Docker Hub, GHCR, or a public
machine while still exercising image push, pull, scan, and remediation flows.

## Start and verify

```bash
docker compose up --build -d
docker compose ps registry
curl http://localhost:5000/v2/
```

The host uses `localhost:5000`; containers on the Compose network use
`registry:5000`. This distinction matters: `localhost` inside the Celery
worker refers to the worker container, not the host.

## Push an image

```bash
docker tag my-image:tag localhost:5000/scrutineering-test:latest
docker push localhost:5000/scrutineering-test:latest
```

Submit `registry:5000/scrutineering-test:latest` in the dashboard scan form.
The worker is configured with `REGISTRY_INSECURE=true` by default so Trivy and
Grype can read the development registry over HTTP. The image is still pulled
through the registry; it is not required to be present in the worker's local
Docker daemon.

## Configuration and reset

These variables are in `.env`:

```dotenv
LOCAL_REGISTRY_PORT=5000
LOCAL_REGISTRY_HOST=registry:5000
REGISTRY_INSECURE=true
GRYPE_REGISTRY_INSECURE_USE_HTTP=true
GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true
```

Registry content persists in the `registrydata` volume. To intentionally
remove local test images, stop the stack and remove only that volume:

```bash
docker compose down
docker volume rm scrutineering_registrydata
```

The built-in registry has no authentication and uses HTTP. It is for local
development only. Production or shared environments must use a TLS-protected,
authenticated registry and set `REGISTRY_INSECURE=false`.
