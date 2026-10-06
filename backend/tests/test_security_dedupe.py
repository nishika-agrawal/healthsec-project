from app.security.dedupe import deduplicate_findings


def make_finding(source, identifier, package, severity):
    return {
        "source": source,
        "identifier": identifier,
        "package_name": package,
        "component": None,
        "normalized_severity": severity,
    }


def test_no_duplicates_returns_all_findings_unchanged():
    findings = [
        make_finding("trivy", "CVE-1", "pkg-a", "HIGH"),
        make_finding("trivy", "CVE-2", "pkg-b", "LOW"),
    ]
    deduped, removed = deduplicate_findings(findings)
    assert len(deduped) == 2
    assert removed == 0


def test_exact_duplicate_is_removed():
    findings = [
        make_finding("trivy", "CVE-1", "pkg-a", "HIGH"),
        make_finding("trivy", "CVE-1", "pkg-a", "HIGH"),
    ]
    deduped, removed = deduplicate_findings(findings)
    assert len(deduped) == 1
    assert removed == 1


def test_conflicting_severity_keeps_the_higher_one():
    findings = [
        make_finding("trivy", "CVE-1", "pkg-a", "LOW"),
        make_finding("trivy", "CVE-1", "pkg-a", "CRITICAL"),
    ]
    deduped, removed = deduplicate_findings(findings)
    assert len(deduped) == 1
    assert removed == 1
    assert deduped[0]["normalized_severity"] == "CRITICAL"


def test_different_sources_with_same_identifier_are_not_merged():
    findings = [
        make_finding("trivy", "CVE-1", "pkg-a", "HIGH"),
        make_finding("dependency_check", "CVE-1", "pkg-a", "HIGH"),
    ]
    deduped, removed = deduplicate_findings(findings)
    assert len(deduped) == 2
    assert removed == 0
