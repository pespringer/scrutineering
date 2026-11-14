"""Run deterministic authenticated GitHub and GitLab provider conformance."""

from src.remediation.provider_fixtures import run_authenticated_provider_fixture


def main() -> None:
    results = [run_authenticated_provider_fixture(provider) for provider in ("github", "gitlab")]
    assert all(result["merged"] and result["status"] == "merged" for result in results)
    for result in results:
        print(f"PASS {result['provider']} authenticated fixture: publication {result['publication_number']} merged ({result['request_count']} requests)")


if __name__ == "__main__":
    main()
