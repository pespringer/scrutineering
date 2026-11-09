# Immutable Image Identity

`src.scan.registry.resolve_image_digest` resolves a local image reference with
`docker image inspect` and accepts only a full lowercase `sha256` digest. A
tag-only reference therefore cannot silently become evidence for a mutable
image: callers must persist the returned digest or treat resolution failure as
non-passing.

The command uses argument-vector execution and never invokes a shell. Registry
API resolution for images that are not present locally remains a follow-up.
