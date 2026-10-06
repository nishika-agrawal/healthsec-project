from app.ml.dataset import (
    FEATURE_COLUMNS,
    RISK_CATEGORIES,
    generate_synthetic_dataset,
    risk_category_from_score,
    rule_based_risk_score,
)


def test_rule_based_score_is_zero_for_no_findings():
    assert rule_based_risk_score({}) == 0.0


def test_rule_based_score_increases_with_critical_findings():
    low = rule_based_risk_score({"critical_count": 0, "high_count": 0})
    high = rule_based_risk_score({"critical_count": 2, "high_count": 0})
    assert high > low


def test_rule_based_score_is_clamped_to_100():
    score = rule_based_risk_score({"critical_count": 50, "high_count": 50, "medium_count": 50})
    assert score == 100.0


def test_rule_based_score_never_negative():
    # A large number of fixes available should not push the score below 0.
    score = rule_based_risk_score({"critical_count": 0, "fix_available_count": 1000})
    assert score >= 0.0


def test_risk_category_thresholds():
    assert risk_category_from_score(0) == "Low"
    assert risk_category_from_score(34.9) == "Low"
    assert risk_category_from_score(35) == "Medium"
    assert risk_category_from_score(69.9) == "Medium"
    assert risk_category_from_score(70) == "High"
    assert risk_category_from_score(100) == "High"


def test_generate_synthetic_dataset_shape_and_columns():
    df = generate_synthetic_dataset(n_samples=200, random_state=1)
    assert len(df) == 200
    for column in FEATURE_COLUMNS:
        assert column in df.columns
    assert "risk_score" in df.columns
    assert "risk_category" in df.columns


def test_generate_synthetic_dataset_has_no_missing_values():
    df = generate_synthetic_dataset(n_samples=200, random_state=1)
    assert df[FEATURE_COLUMNS].isnull().sum().sum() == 0


def test_generate_synthetic_dataset_categories_are_valid():
    df = generate_synthetic_dataset(n_samples=200, random_state=1)
    assert set(df["risk_category"].unique()).issubset(set(RISK_CATEGORIES))


def test_generate_synthetic_dataset_is_reproducible_with_same_seed():
    df1 = generate_synthetic_dataset(n_samples=100, random_state=7)
    df2 = generate_synthetic_dataset(n_samples=100, random_state=7)
    assert df1.equals(df2)


def test_generate_synthetic_dataset_differs_with_different_seed():
    df1 = generate_synthetic_dataset(n_samples=100, random_state=1)
    df2 = generate_synthetic_dataset(n_samples=100, random_state=2)
    assert not df1.equals(df2)
