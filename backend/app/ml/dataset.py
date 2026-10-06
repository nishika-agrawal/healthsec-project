"""
Synthetic vulnerability-risk dataset for prototype training.

IMPORTANT - READ BEFORE USING THIS DATA FOR ANYTHING BEYOND THIS DEMO:

- No public dataset maps "security scan feature vectors" directly onto a
  real deployment-risk outcome (e.g. "this build later caused an
  incident"). That kind of labeled, outcome-based data is sensitive and
  proprietary to organizations that experience real incidents, and isn't
  published for reuse.
- This module therefore GENERATES a synthetic dataset instead:
    1. Feature values (vulnerability counts, CVSS scores, etc.) are drawn
       from distributions chosen to *look like* real scan output - most
       scans have zero or a few critical findings, many low-severity
       findings are common, and so on.
    2. The "ground truth" risk_category label for each synthetic row is
       computed by a documented, deterministic scoring rule
       (rule_based_risk_score, below) - NOT observed from any real
       outcome.
    3. A small amount of random label noise is added, so the dataset
       isn't trivially, perfectly separable (which would make the model
       look artificially perfect and would be a misleading demo).
- Because the labels come from a fixed rule rather than real historical
  outcomes, a model trained on this data learns to approximate that
  rule - not real-world deployment risk. This project explicitly does
  NOT claim real-world predictive accuracy from this synthetic data. It
  demonstrates the full ML + Explainable AI pipeline end-to-end, which
  is the goal for this academic project. Replacing this dataset with
  real, outcome-labeled historical scan data is listed as a future
  enhancement (see Phase 12 documentation).
"""

import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "max_cvss_score",
    "max_cvss_score_missing",
    "vulnerable_dependency_count",
    "container_vulnerability_count",
    "failed_security_checks",
    "fix_available_count",
    "total_findings",
]

RISK_CATEGORIES = ["Low", "Medium", "High"]


def rule_based_risk_score(features: dict) -> float:
    """
    A fixed, documented, weighted-sum scoring rule, clamped to 0-100.

    This is used for two different purposes in this project:
      (a) to generate the ground-truth labels for the synthetic training
          data (see generate_synthetic_dataset below), and
      (b) as the fallback risk score whenever no trained model is
          available (see predictor.py) - so the application always
          produces *some* risk assessment, never a crash.

    This is NOT a machine-learning prediction - it is a transparent,
    inspectable formula. The weights were chosen to reflect a reasonable,
    common-sense prioritization (critical findings matter far more than
    low-severity ones), not fit to any data.
    """
    critical = features.get("critical_count", 0) or 0
    high = features.get("high_count", 0) or 0
    medium = features.get("medium_count", 0) or 0
    low = features.get("low_count", 0) or 0
    max_cvss = features.get("max_cvss_score") or 0
    failed_checks = features.get("failed_security_checks", 0) or 0
    fix_available = features.get("fix_available_count", 0) or 0

    score = (
        critical * 25
        + high * 12
        + medium * 5
        + low * 1
        + max_cvss * 2
        + failed_checks * 8
        - fix_available * 1.5  # readily-fixable findings are slightly less urgent
    )
    return float(max(0.0, min(100.0, score)))


def risk_category_from_score(score: float) -> str:
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _sample_feature_row(rng: np.random.Generator) -> dict:
    """Draws one synthetic scan's feature values from distributions shaped like real scan output."""
    critical_count = int(rng.poisson(0.3))
    high_count = int(rng.poisson(0.8))
    medium_count = int(rng.poisson(1.5))
    low_count = int(rng.poisson(2.5))

    total_findings = critical_count + high_count + medium_count + low_count

    has_cvss_data = rng.random() > 0.15  # ~15% of scans have no CVSS-bearing findings at all
    if has_cvss_data and total_findings > 0:
        max_cvss_score = float(np.clip(rng.normal(loc=5.5, scale=2.5), 0, 10))
    else:
        max_cvss_score = None

    vulnerable_dependency_count = int(rng.poisson(1.2))
    container_vulnerability_count = int(rng.poisson(1.0))
    failed_security_checks = int(rng.binomial(3, 0.15))
    fix_available_count = int(rng.binomial(total_findings, 0.5)) if total_findings > 0 else 0

    return {
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "max_cvss_score": max_cvss_score,
        "max_cvss_score_missing": max_cvss_score is None,
        "vulnerable_dependency_count": vulnerable_dependency_count,
        "container_vulnerability_count": container_vulnerability_count,
        "failed_security_checks": failed_security_checks,
        "fix_available_count": fix_available_count,
        "total_findings": total_findings,
    }


def generate_synthetic_dataset(
    n_samples: int = 2000, noise_level: float = 0.08, random_state: int = 42
) -> pd.DataFrame:
    """
    Generates a synthetic dataset of n_samples rows: feature columns plus
    'risk_score' (0-100, from the rule) and 'risk_category' (Low/Medium/
    High, from the rule, with noise_level fraction of labels randomly
    reassigned to a different category to simulate real-world label
    uncertainty and avoid a trivially perfect classification problem).

    random_state is fixed by default so the generated dataset - and
    therefore model training - is reproducible.
    """
    rng = np.random.default_rng(random_state)
    rows = []

    for _ in range(n_samples):
        row = _sample_feature_row(rng)
        score = rule_based_risk_score(row)
        category = risk_category_from_score(score)

        if rng.random() < noise_level:
            category = rng.choice([c for c in RISK_CATEGORIES if c != category])

        row["risk_score"] = round(score, 2)
        row["risk_category"] = category
        rows.append(row)

    df = pd.DataFrame(rows)

    # Cleaning step: max_cvss_score is None for rows with no CVSS-bearing
    # findings. Rather than dropping those rows (which would bias the
    # dataset toward scans that happen to have CVSS data), impute 0 and
    # keep the max_cvss_score_missing flag so the model can still tell
    # the difference between "confirmed CVSS 0" and "no CVSS data at all".
    df["max_cvss_score"] = df["max_cvss_score"].fillna(0.0)
    df["max_cvss_score_missing"] = df["max_cvss_score_missing"].astype(int)

    return df
