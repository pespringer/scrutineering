# Immutable Image Identity

`src.scan.registry.resolve_image_digest` resolves a local image reference with
`docker image inspect` and accepts only a full lowercase `sha256` digest. A
tag-only reference therefore cannot silently become evidence for a mutable
image: callers must persist the returned digest or treat resolution failure as
non-passing.

The command uses argument-vector execution and never invokes a shell. Registry
API resolution for images that are not present locally remains a follow-up.

Set `REQUIRE_IMMUTABLE_SCAN_IDENTITY=true` in production. The scan service then
refuses to run scanners when a tag cannot be resolved, and passes the resolved
`repository@sha256:...` reference to every scanner and persistence boundary.
