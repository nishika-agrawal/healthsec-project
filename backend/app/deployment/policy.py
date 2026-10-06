"""
Deployment decision policy.

Default policy (the mandatory-scanner list is configurable via the
DEPLOYMENT_MANDATORY_SCANNERS environment variable - see app/config.py):

- Low risk    -> approved, PROVIDED all mandatory security checks passed.
- Medium risk -> review_required (a human must approve before deploying).
- High risk   -> blocked until the identified issues are remediated.

Two rules override the above and apply FIRST, before risk category is
even considered:

1. If the predicted risk category itself isn't a recognized value
   (e.g. the prediction pipeline failed or returned something
   unexpected), deployment is BLOCKED. It is never approved just
   because a category couldn't be determined.
2. If ANY mandatory scanner's status is not exactly "ok" - meaning it
   is missing, invalid, or reported itself unavailable - deployment is
   BLOCKED, regardless of how low the predicted risk is. A scan that
   didn't actually run is not evidence of safety.

This means a build can never be auto-approved based on incomplete or
failed data, and an invalid prediction can never slip through as an
approval.
"""

from typing import Optional

DEFAULT_MANDATORY_SCANNERS = ["trivy", "dependency_check", "sonarqube"]
VALID_RISK_CATEGORIES = {"Low", "Medium", "High"}

DECISION_APPROVED = "approved"
DECISION_REVIEW_REQUIRED = "review_required"
DECISION_BLOCKED = "blocked"


def mandatory_checks_passed(scanner_status: dict, mandatory_scanners: Optional[list] = None) -> "tuple[bool, list]":
    """
    Returns (all_passed, failed_scanner_names).

    A scanner "passes" only if its recorded status is exactly "ok" -
    "missing", "invalid", and "tool_unavailable" are all treated as
    failures, since none of them confirm the code was actually scanned
    successfully.
    """
    mandatory = mandatory_scanners if mandatory_scanners is not None else DEFAULT_MANDATORY_SCANNERS
    failed = [name for name in mandatory if scanner_status.get(name) != "ok"]
    return len(failed) == 0, failed


def decide_deployment(
    risk_category: str,
    scanner_status: dict,
    mandatory_scanners: Optional[list] = None,
) -> dict:
    """
    Returns:
        {
            "decision": "approved" | "review_required" | "blocked",
            "reason": str,                    # human-readable explanation
            "mandatory_checks_passed": bool,
            "failed_checks": [scanner names that failed, if any],
            "risk_category": the input risk_category, echoed back,
        }
    """
    checks_passed, failed_checks = mandatory_checks_passed(scanner_status, mandatory_scanners)

    if risk_category not in VALID_RISK_CATEGORIES:
        return {
            "decision": DECISION_BLOCKED,
            "reason": (
                f"Invalid or unavailable risk category ('{risk_category}') - deployment cannot be "
                "approved without a valid risk assessment."
            ),
            "mandatory_checks_passed": checks_passed,
            "failed_checks": failed_checks,
            "risk_category": risk_category,
        }

    if not checks_passed:
        return {
            "decision": DECISION_BLOCKED,
            "reason": (
                f"Mandatory security checks failed or did not run: {', '.join(failed_checks)}. "
                "Deployment is blocked regardless of the predicted risk level."
            ),
            "mandatory_checks_passed": False,
            "failed_checks": failed_checks,
            "risk_category": risk_category,
        }

    if risk_category == "Low":
        return {
            "decision": DECISION_APPROVED,
            "reason": "Risk assessed as Low and all mandatory security checks passed.",
            "mandatory_checks_passed": True,
            "failed_checks": [],
            "risk_category": risk_category,
        }

    if risk_category == "Medium":
        return {
            "decision": DECISION_REVIEW_REQUIRED,
            "reason": (
                "Risk assessed as Medium. All mandatory checks passed, but manual review/approval "
                "is required before deployment."
            ),
            "mandatory_checks_passed": True,
            "failed_checks": [],
            "risk_category": risk_category,
        }

    # High
    return {
        "decision": DECISION_BLOCKED,
        "reason": "Risk assessed as High. Deployment is blocked until the identified issues are remediated.",
        "mandatory_checks_passed": True,
        "failed_checks": [],
        "risk_category": risk_category,
    }
