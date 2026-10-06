from app.xai.recommendations import generate_recommendations


def make_finding(**overrides):
    base = {
        "source": "trivy",
        "identifier": "CVE-0000",
        "normalized_severity": "LOW",
        "package_name": "example-pkg",
        "installed_version": "1.0.0",
        "fixed_version": None,
        "fix_available": False,
        "title": "Example finding",
        "component": "example-target",
        "cvss_score": None,
        "finding_class": None,
    }
    base.update(overrides)
    return base


def test_critical_and_high_findings_each_get_a_recommendation():
    findings = [
        make_finding(identifier="CVE-1", normalized_severity="CRITICAL"),
        make_finding(identifier="CVE-2", normalized_severity="HIGH"),
        make_finding(identifier="CVE-3", normalized_severity="MEDIUM"),
        make_finding(identifier="CVE-4", normalized_severity="LOW"),
    ]
    result = generate_recommendations(findings)

    assert len(result["recommendations"]) == 2
    identifiers = {r["linked_finding"]["identifier"] for r in result["recommendations"]}
    assert identifiers == {"CVE-1", "CVE-2"}


def test_medium_and_low_findings_are_only_counted_not_listed():
    findings = [
        make_finding(identifier="CVE-1", normalized_severity="MEDIUM"),
        make_finding(identifier="CVE-2", normalized_severity="MEDIUM"),
        make_finding(identifier="CVE-3", normalized_severity="LOW"),
    ]
    result = generate_recommendations(findings)

    assert result["recommendations"] == []
    assert result["summary"]["medium_noted"] == 2
    assert result["summary"]["low_noted"] == 1


def test_recommendations_are_sorted_critical_first():
    findings = [
        make_finding(identifier="CVE-HIGH", normalized_severity="HIGH"),
        make_finding(identifier="CVE-CRITICAL", normalized_severity="CRITICAL"),
    ]
    result = generate_recommendations(findings)

    priorities = [r["priority"] for r in result["recommendations"]]
    assert priorities == ["CRITICAL", "HIGH"]


def test_container_finding_recommends_docker_image_rebuild():
    findings = [
        make_finding(
            identifier="CVE-OS-1",
            normalized_severity="CRITICAL",
            source="trivy",
            finding_class="os-pkgs",
            package_name="libssl3",
            installed_version="3.0.11",
            fixed_version="3.0.13",
            fix_available=True,
        )
    ]
    result = generate_recommendations(findings)
    rec = result["recommendations"][0]

    assert rec["category"] == "container_update"
    assert "Rebuild the Docker image" in rec["action"]
    assert "libssl3" in rec["action"]
    assert "3.0.13" in rec["action"]


def test_dependency_finding_recommends_upgrade():
    findings = [
        make_finding(
            identifier="CVE-DEP-1",
            normalized_severity="HIGH",
            source="dependency_check",
            package_name="example-lib-1.0.0.jar",
            fixed_version="1.2.0",
            fix_available=True,
        )
    ]
    result = generate_recommendations(findings)
    rec = result["recommendations"][0]

    assert rec["category"] == "dependency_upgrade"
    assert "Upgrade" in rec["action"]
    assert "1.2.0" in rec["action"]


def test_finding_without_fix_available_gives_monitoring_advice_not_a_fabricated_fix():
    findings = [
        make_finding(
            identifier="CVE-NOFIX",
            normalized_severity="CRITICAL",
            source="dependency_check",
            package_name="example-lib",
            fixed_version=None,
            fix_available=False,
        )
    ]
    result = generate_recommendations(findings)
    rec = result["recommendations"][0]

    assert "No fixed version is currently available" in rec["action"]
    assert "None" not in rec["action"]  # never print a literal "None" as if it were a version


def test_sonarqube_finding_recommends_code_review():
    findings = [
        make_finding(
            identifier="python:S105",
            normalized_severity="HIGH",
            source="sonarqube",
            package_name=None,
            component="backend/app/config.py",
            title="Hard-coded credential-like value",
            fix_available=False,
        )
    ]
    result = generate_recommendations(findings)
    rec = result["recommendations"][0]

    assert rec["category"] == "code_review"
    assert "backend/app/config.py" in rec["action"]


def test_every_recommendation_is_linked_to_its_source_finding():
    findings = [
        make_finding(identifier="CVE-LINK-TEST", normalized_severity="CRITICAL", component="some/target"),
    ]
    result = generate_recommendations(findings)
    rec = result["recommendations"][0]

    assert rec["linked_finding"]["identifier"] == "CVE-LINK-TEST"
    assert rec["linked_finding"]["source"] == "trivy"


def test_empty_findings_list_produces_no_recommendations():
    result = generate_recommendations([])
    assert result["recommendations"] == []
    assert result["summary"] == {
        "critical_count": 0,
        "high_count": 0,
        "medium_noted": 0,
        "low_noted": 0,
        "unknown_noted": 0,
    }
