from src.remediation.provider_fixtures import run_authenticated_provider_fixture


def test_authenticated_provider_fixtures_cover_github_and_gitlab():
    results = [run_authenticated_provider_fixture(provider) for provider in ("github", "gitlab")]

    assert {result["provider"] for result in results} == {"github", "gitlab"}
    assert all(result["publication_number"] == 101 for result in results)
    assert all(result["status"] == "merged" and result["merged"] for result in results)
    assert all(result["request_count"] == 3 for result in results)
