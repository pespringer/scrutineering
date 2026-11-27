# Scanner errors

What Trivy 0.76.2 and Grype 0.121.2 wrote to stderr in the worker image, run as
`src/scan/scanners/` runs them, for `tests/test_scanner_errors.py`
([docs/design/scan-errors.md](../../docs/design/scan-errors.md)). `*-findings` exited 0;
every other file exited 1.

- `refused`: nothing listening (`registry:5999`).
- `no-such-tag`: the local registry, a tag that doesn't exist.
- `unauthorized`: a Docker Hub repository that doesn't exist, without credentials.
- `http-only`: the local registry over HTTPS, without `REGISTRY_INSECURE`.
- `findings`: the golden-path fixture image, scanned successfully.

`trivy-refused` also shows Trivy downloading its vulnerability database first.
