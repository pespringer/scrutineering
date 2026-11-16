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
The worker is configured with `REGISTRY_INSECURE=true` by default, which lets
Trivy and Grype read **this registry** (`LOCAL_REGISTRY_HOST`, and `localhost`)
over HTTP. Every other registry still uses TLS. Before scanning, the worker
resolves the tag to its digest and scans `registry:5000/repo@sha256:...`, so a
rescan after pushing a new image under the same tag scans the new content. The
image is read from the registry; it does not need to be in a local Docker daemon.

## Manage images in the dashboard

Open `http://localhost:3001/images`. The Registry catalog section shows every
repository tag, digest, last scan time, open finding counts, and a security
state of `Not scanned`, `Scanning`, `Clean`, `Issues found`, or `Scan failed`.
Use **Scan image** or **Rescan** to submit a normal-priority scan. Once the
worker finishes, use **Details** to open the existing finding and remediation
workflow for that exact registry image.

## Configuration and reset

These variables are in `.env`:

```dotenv
LOCAL_REGISTRY_PORT=5000
LOCAL_REGISTRY_HOST=registry:5000
LOCAL_REGISTRY_PUBLIC_HOST=localhost:5000
LOCAL_REGISTRY_PUBLIC_URL=http://localhost:5000
REGISTRY_INSECURE=true
```

Older `.env` files may also set `GRYPE_REGISTRY_INSECURE_USE_HTTP` and
`GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY`. They are now ignored: the worker sets
them per scan, only for the local registry.

Registry content persists in the `registrydata` volume. To intentionally
remove local test images, stop the stack and remove only that volume:

```bash
docker compose down
docker volume rm scrutineering_registrydata
```

The built-in registry has no authentication and uses HTTP. It is for local
development only. Production or shared environments must use a TLS-protected,
authenticated registry and set `REGISTRY_INSECURE=false`.
