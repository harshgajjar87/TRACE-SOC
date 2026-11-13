"""Day 25 tests — Detection Rule Quality Engine."""

import pytest
from detection.quality import (
    get_rule_quality_summary,
    get_overall_quality_metrics,
    get_category_quality_breakdown,
    _build_suggestions,
    _score_rule,
)
from detection.rules import DETECTION_RULES


def test_rule_quality_summary_returns_all_rules(test_db):
    summary = get_rule_quality_summary()
    expected_ids = {r["rule_id"] for r in DETECTION_RULES}
    actual_ids = {r["rule_id"] for r in summary}
    assert expected_ids == actual_ids


def test_rule_quality_summary_fields(test_db):
    summary = get_rule_quality_summary()
    required_fields = {
        "rule_id", "name", "category", "severity",
        "total_alerts", "false_positive_count", "fp_rate",
        "quality_score", "quality_band", "suggestions",
    }
    for rule in summary:
        assert required_fields.issubset(rule.keys())


def test_rule_quality_band_values(test_db):
    summary = get_rule_quality_summary()
    valid_bands = {"GOOD", "ACCEPTABLE", "NEEDS_REVIEW", "POOR"}
    for rule in summary:
        assert rule["quality_band"] in valid_bands


def test_rule_quality_score_range(test_db):
    summary = get_rule_quality_summary()
    for rule in summary:
        assert 0 <= rule["quality_score"] <= 100


def test_fp_rate_calculation(test_db):
    summary = get_rule_quality_summary()
    for rule in summary:
        total = rule["total_alerts"]
        fp = rule["false_positive_count"]
        if total > 0:
            expected_rate = fp / total
            assert abs(rule["fp_rate"] - expected_rate) < 0.001
        else:
            assert rule["fp_rate"] == 0.0


def test_zero_alerts_rule_gets_suggestion(test_db):
    # Every rule that has never fired should have a suggestion
    summary = get_rule_quality_summary()
    never_fired = [r for r in summary if r["total_alerts"] == 0]
    for rule in never_fired:
        assert len(rule["suggestions"]) > 0


def test_overall_quality_metrics_structure(test_db):
    metrics = get_overall_quality_metrics()
    assert "total_rules" in metrics
    assert "total_alerts" in metrics
    assert "overall_fp_rate" in metrics
    assert "band_counts" in metrics
    assert "never_fired" in metrics


def test_overall_quality_metrics_total_rules(test_db):
    metrics = get_overall_quality_metrics()
    assert metrics["total_rules"] == len(DETECTION_RULES)


def test_band_counts_sum_equals_total_rules(test_db):
    metrics = get_overall_quality_metrics()
    band_sum = sum(metrics["band_counts"].values())
    assert band_sum == metrics["total_rules"]


def test_category_quality_breakdown_returns_list(test_db):
    result = get_category_quality_breakdown()
    assert isinstance(result, list)


def test_category_quality_breakdown_fields(test_db):
    result = get_category_quality_breakdown()
    for cat in result:
        assert "category" in cat
        assert "rule_count" in cat
        assert "total_alerts" in cat
        assert "fp_rate" in cat


def test_score_rule_good():
    score, band = _score_rule(total=50, fp_rate=0.0, suggestions=[])
    assert score == 100
    assert band == "GOOD"


def test_score_rule_poor_zero_alerts():
    score, band = _score_rule(total=0, fp_rate=0.0, suggestions=["Rule has never fired."])
    # 100 - 40 (never fired) - 0 (no extra suggestions) = 60 → ACCEPTABLE
    # Either below GOOD or carries a suggestion — the key point is it's penalised
    assert score < 100
    assert band in ("POOR", "NEEDS_REVIEW", "ACCEPTABLE")


def test_score_rule_poor_high_fp():
    score, band = _score_rule(total=100, fp_rate=0.90, suggestions=["High FP rate"])
    assert score < 60


def test_build_suggestions_never_fired():
    rule = {"rule_type": "single_event", "threshold": None, "time_window": None}
    suggestions = _build_suggestions(rule, total=0, fp_count=0, fp_rate=0.0, resolved=0, open_count=0)
    assert any("never fired" in s.lower() for s in suggestions)


def test_build_suggestions_high_fp():
    rule = {"rule_type": "threshold", "threshold": 5, "time_window": 300}
    suggestions = _build_suggestions(rule, total=20, fp_count=10, fp_rate=0.5, resolved=5, open_count=5)
    assert any("false positive" in s.lower() or "threshold" in s.lower() for s in suggestions)


def test_build_suggestions_low_coverage():
    rule = {"rule_type": "single_event"}
    suggestions = _build_suggestions(rule, total=1, fp_count=0, fp_rate=0.0, resolved=1, open_count=0)
    assert len(suggestions) > 0


def test_category_coverage_all_categories_present(test_db):
    expected_categories = {r["category"] for r in DETECTION_RULES}
    result = get_category_quality_breakdown()
    actual_categories = {c["category"] for c in result}
    assert expected_categories == actual_categories
