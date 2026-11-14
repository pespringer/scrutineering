from src.scan.runtime_discovery import is_scannable_runtime_image, safe_runtime_context, select_runtime_images


def test_runtime_discovery_filters_and_deduplicates_images():
    containers = [
        {"id": "one", "names": "api-1", "image": "acme/api:latest", "labels": {"scan": "yes"}},
        {"id": "two", "names": "api-2", "image": "acme/api:latest", "labels": {"scan": "yes"}},
        {"id": "three", "names": "db-1", "image": "postgres:16", "labels": {"scan": "yes"}},
    ]

    assert select_runtime_images(containers, include=["acme/*"], include_label="scan=yes") == ["acme/api:latest"]


def test_runtime_discovery_excludes_container_names_and_images():
    containers = [
        {"id": "one", "names": "api-dev", "image": "acme/api:dev"},
        {"id": "two", "names": "api-prod", "image": "acme/api:prod"},
    ]

    assert select_runtime_images(containers, exclude=["*:dev"], exclude_containers=["api-prod"]) == []


def test_runtime_discovery_skips_non_pullable_runtime_metadata():
    containers = [
        {"image": "sha256:" + "a" * 64},
        {"image": "local/source-fixture:filesystem"},
        {"image": "other/fs:/workspace/repository:latest"},
        {"image": "other/invalid.invalid/image:never"},
        {"image": "nginx:1.25"},
    ]

    assert select_runtime_images(containers) == ["nginx:1.25"]
    assert is_scannable_runtime_image("nginx:1.25")
    assert not is_scannable_runtime_image("sha256:" + "a" * 64)


def test_runtime_context_allows_workload_coordinates_but_redacts_arbitrary_labels():
    container = {
        "labels": {
            "com.docker.compose.project": "payments",
            "com.docker.compose.service": "api",
            "app.kubernetes.io/part-of": "platform",
            "SECRET_TOKEN": "do-not-return",
        }
    }

    assert safe_runtime_context(container) == {"project": "payments", "service": "api", "owner": "platform"}
