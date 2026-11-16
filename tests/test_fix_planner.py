"""How findings are classified and grouped into fix actions."""

from src.remediation.planner import FindingInput, classify, first_fixed_version, plan, version_key


def _finding(id, package, version, package_type, fixed, vuln_key=None):
    return FindingInput(
        id=id,
        vuln_key=vuln_key or f"key-{id}",
        cve_id=f"CVE-2026-{id}",
        package_name=package,
        package_version=version,
        package_type=package_type,
        fixed_version=fixed,
    )


def test_versions_compare_numerically():
    assert version_key("3.0.19-r0") > version_key("3.0.9-r1")
    assert version_key("4.17.21") > version_key("4.17.3")
    assert first_fixed_version("5.0.0, 4.17.21") == "4.17.21"
    assert first_fixed_version("") is None


def test_each_package_type_maps_to_a_strategy():
    assert classify(_finding(1, "lodash", "4.17.20", "node-pkg", "4.17.21"))[0] == "dependency_update"
    assert classify(_finding(2, "lodash", "4.17.20", "npm", "4.17.21"))[0] == "dependency_update"
    assert classify(_finding(3, "requests", "2.0", "python-pkg", "2.1"))[0] == "dependency_update"
    assert classify(_finding(4, "libssl3", "3.0.7-r0", "alpine", "3.0.19-r0"))[0] == "os_package_upgrade"
    assert classify(_finding(5, "node", "18.12.1", "binary", "18.20.0"))[0] == "base_image_bump"
    strategy, reason = classify(_finding(6, "libssl3", "3.0.7-r0", "apk", None))
    assert strategy == "manual" and "No fixed version" in reason
    strategy, reason = classify(_finding(7, "serde", "1.0", "cargo", "1.1"))
    assert strategy == "manual" and "cargo" in reason


def test_trivy_and_grype_findings_for_one_package_become_one_action():
    findings = [
        _finding(1, "lodash", "4.17.20", "node-pkg", "4.17.21", vuln_key="a"),
        _finding(2, "lodash", "4.17.20", "npm", "4.17.21", vuln_key="a"),
        _finding(3, "lodash", "4.17.20", "npm", "4.17.19, 4.17.21", vuln_key="b"),
    ]
    result = plan(findings)
    assert len(result.actions) == 1
    action = result.actions[0].as_dict()
    assert (action["package"], action["ecosystem"], action["to_version"]) == ("lodash", "npm", "4.17.21")
    assert action["finding_ids"] == [1, 2, 3]
    assert action["vuln_keys"] == ["a", "b"]


def test_os_packages_share_one_upgrade_with_the_highest_minimum_version():
    result = plan(
        [
            _finding(1, "libssl3", "3.0.7-r0", "alpine", "3.0.14-r0"),
            _finding(2, "libssl3", "3.0.7-r0", "alpine", "3.0.19-r0"),
            _finding(3, "libcrypto3", "3.0.7-r0", "alpine", "3.0.19-r0"),
            _finding(4, "busybox", "1.35", "apk", None),
        ]
    )
    assert [action.strategy for action in result.actions] == ["os_package_upgrade"]
    assert result.actions[0].packages == {"libcrypto3": "3.0.19-r0", "libssl3": "3.0.19-r0"}
    assert [item.finding_id for item in result.manual] == [4]
    assert result.actionable_finding_ids == {1, 2, 3}
