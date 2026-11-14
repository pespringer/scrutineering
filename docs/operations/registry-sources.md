# Registry sources

The dashboard `/sources` page stores source names and registry hosts without
storing credentials. Credentials remain in the deployment environment and are
identified only by the variable names required by the selected registry.

Use **Check with tagged image** to perform a read-only OCI manifest lookup. A
successful check records the immutable digest, timestamp, and source status;
failures record a redacted classification and remain visible in the source
record and audit trail. The check never pulls an image or returns a token.

Examples:

- `ghcr.io/example/service:v1.2.3`
- `registry.example.com/team/service:stable`
- `nginx:1.27` for Docker Hub

The source check is a connectivity and credential test, not a vulnerability
scan. Once a source is ready, select it in Scan history and provide the tagged
reference. Scrutineering validates that the reference belongs to the selected
source, then queues the canonical registry coordinate for the worker. Manual
image references remain supported for public images and backwards compatibility.
