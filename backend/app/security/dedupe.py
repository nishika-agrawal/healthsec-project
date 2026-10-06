"""
Removes duplicate findings.

A duplicate is defined as the same (source, identifier, package/component)
combination appearing more than once - which can genuinely happen, e.g.
Trivy sometimes lists the same CVE against the same package under more
than one scan target.

When duplicates conflict on severity (rare, but possible if a scanner is
inconsistent within one report), the highest-severity copy is kept, so
deduplication can never make a scan look safer than the raw data supports.
"""

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _dedupe_key(finding: dict):
    return (
        finding.get("source"),
        finding.get("identifier"),
        finding.get("package_name") or finding.get("component"),
    )


def deduplicate_findings(findings: list) -> "tuple[list, int]":
    """
    Returns (deduplicated_findings, number_of_duplicates_removed).
    """
    kept: dict = {}

    for finding in findings:
        key = _dedupe_key(finding)
        existing = kept.get(key)

        if existing is None:
            kept[key] = finding
            continue

        existing_rank = _SEVERITY_RANK.get(existing.get("normalized_severity"), 0)
        new_rank = _SEVERITY_RANK.get(finding.get("normalized_severity"), 0)
        if new_rank > existing_rank:
            kept[key] = finding

    deduped = list(kept.values())
    duplicates_removed = len(findings) - len(deduped)
    return deduped, duplicates_removed
