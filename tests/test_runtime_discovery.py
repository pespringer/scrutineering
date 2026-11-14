from src.scan.runtime_discovery import select_runtime_images


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
