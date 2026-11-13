"""
TRACE-SOC Day 25 — Detection Rule Quality Engine

Scores each detection rule against stored alert data to surface
false-positive rates, firing frequency, coverage gaps and tuning
suggestions. All calculations are based on analyst feedback in the
alerts table; they are heuristic indicators, not statistical proofs.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from database.db import get_connection
from detection.rules import DETECTION_RULES

# Analyst status values that indicate a false positive
FALSE_POSITIVE_STATUSES = {"FALSE_POSITIVE"}

# Alert counts below this threshold indicate low-coverage rules
LOW_COVERAGE_THRESHOLD = 3

# False positive rate above this fraction warrants a tuning suggestion
HIGH_FP_RATE_THRESHOLD = 0.30


def _dict_rows(rows):
    return [dict(row) for row in rows]


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_rule_quality_summary() -> list[dict]:
    """
    Return a quality record for every configured detection rule.

    Fields returned per rule:
      rule_id, name, category, severity, mitre_technique
      total_alerts        — total alerts produced by the rule
      false_positive_count — alerts marked FALSE_POSITIVE
      fp_rate             — false_positive_count / total_alerts (0 if none)
      resolved_count      — alerts marked RESOLVED
      open_count          — NEW or INVESTIGATING alerts
      quality_score       — 0–100 heuristic score
      quality_band        — GOOD / ACCEPTABLE / NEEDS_REVIEW / POOR
      suggestions         — list of human-readable tuning suggestions
    """
    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        # Aggregate alert counts per rule_id broken down by status
        rows = connection.execute("""
            SELECT
                rule_id,
                status,
                COUNT(*) AS cnt
            FROM alerts
            GROUP BY rule_id, status
        """).fetchall()
    finally:
        connection.close()

    # Build a dict: rule_id -> {status: count, ...}
    rule_stats: dict[str, dict[str, int]] = {}
    for row in rows:
        rid = row["rule_id"]
        if rid not in rule_stats:
            rule_stats[rid] = {}
        rule_stats[rid][row["status"]] = row["cnt"]

    results = []
    for rule in DETECTION_RULES:
        rid = rule["rule_id"]
        stats = rule_stats.get(rid, {})

        total = sum(stats.values())
        fp_count = stats.get("FALSE_POSITIVE", 0)
        resolved = stats.get("RESOLVED", 0)
        open_count = stats.get("NEW", 0) + stats.get("INVESTIGATING", 0)

        fp_rate = fp_count / total if total > 0 else 0.0

        suggestions = _build_suggestions(
            rule, total, fp_count, fp_rate, resolved, open_count
        )

        quality_score, quality_band = _score_rule(
            total, fp_rate, suggestions
        )

        results.append({
            "rule_id": rid,
            "name": rule.get("name", ""),
            "category": rule.get("category", ""),
            "severity": rule.get("severity", ""),
            "mitre_technique": rule.get("mitre_technique", ""),
            "mitre_tactic": rule.get("mitre_tactic", ""),
            "total_alerts": total,
            "false_positive_count": fp_count,
            "fp_rate": round(fp_rate, 4),
            "resolved_count": resolved,
            "open_count": open_count,
            "quality_score": quality_score,
            "quality_band": quality_band,
            "suggestions": suggestions,
        })

    # Sort: POOR first, then NEEDS_REVIEW, then by rule_id
    band_order = {"POOR": 0, "NEEDS_REVIEW": 1, "ACCEPTABLE": 2, "GOOD": 3}
    results.sort(key=lambda r: (band_order.get(r["quality_band"], 9), r["rule_id"]))
    return results


def _build_suggestions(rule, total, fp_count, fp_rate, resolved, open_count):
    suggestions = []

    if total == 0:
        suggestions.append(
            "Rule has never fired. Verify telemetry is reaching the detection engine."
        )

    elif total < LOW_COVERAGE_THRESHOLD:
        suggestions.append(
            f"Rule fired only {total} time(s). Confirm target event sources are being collected."
        )

    if fp_rate > HIGH_FP_RATE_THRESHOLD and total > 0:
        pct = round(fp_rate * 100, 1)
        suggestions.append(
            f"{pct}% false positive rate. Consider tightening threshold, adding "
            "suppression conditions, or refining keyword/indicator lists."
        )

    if open_count > 20:
        suggestions.append(
            f"{open_count} open alerts not yet triaged. Review analyst workload or "
            "consider automating initial triage for lower-severity variants."
        )

    # Rule-type-specific hints
    rule_type = rule.get("rule_type", "")
    if rule_type == "threshold" and fp_rate > 0.2:
        threshold = rule.get("threshold")
        window = rule.get("time_window")
        suggestions.append(
            f"Threshold rule: current threshold={threshold}, window={window}s. "
            "Raising the threshold or narrowing the time window may reduce false positives."
        )

    if rule_type == "keyword" and fp_rate > 0.2:
        suggestions.append(
            "Keyword rule with elevated FP rate. Audit keyword list for overly broad terms "
            "or add suppression conditions for known-good processes."
        )

    if rule_type == "single_event" and total > 100 and fp_rate > 0.15:
        suggestions.append(
            "Single-event rule firing frequently with false positives. "
            "Add allowlist conditions or consider correlating with other events."
        )

    return suggestions


def _score_rule(total, fp_rate, suggestions):
    """Return (score 0-100, quality_band string)."""
    score = 100

    # Penalise for never firing
    if total == 0:
        score -= 40

    # Penalise proportionally for false positive rate
    score -= int(fp_rate * 60)

    # Small penalty per suggestion beyond the first
    extra_suggestions = max(0, len(suggestions) - 1)
    score -= extra_suggestions * 5

    score = max(0, min(100, score))

    if score >= 80:
        band = "GOOD"
    elif score >= 60:
        band = "ACCEPTABLE"
    elif score >= 35:
        band = "NEEDS_REVIEW"
    else:
        band = "POOR"

    return score, band


def get_overall_quality_metrics() -> dict:
    """Return aggregate quality metrics across all rules."""
    summary = get_rule_quality_summary()

    band_counts = {"GOOD": 0, "ACCEPTABLE": 0, "NEEDS_REVIEW": 0, "POOR": 0}
    total_alerts = 0
    total_fp = 0
    never_fired = 0

    for r in summary:
        band_counts[r["quality_band"]] = band_counts.get(r["quality_band"], 0) + 1
        total_alerts += r["total_alerts"]
        total_fp += r["false_positive_count"]
        if r["total_alerts"] == 0:
            never_fired += 1

    overall_fp_rate = total_fp / total_alerts if total_alerts > 0 else 0.0

    return {
        "total_rules": len(summary),
        "total_alerts": total_alerts,
        "total_false_positives": total_fp,
        "overall_fp_rate": round(overall_fp_rate, 4),
        "never_fired": never_fired,
        "band_counts": band_counts,
        "assessed_at_utc": _utc_now(),
    }


def get_category_quality_breakdown() -> list[dict]:
    """Return quality metrics grouped by detection category."""
    summary = get_rule_quality_summary()

    categories: dict[str, dict] = {}
    for r in summary:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {
                "category": cat,
                "rule_count": 0,
                "total_alerts": 0,
                "total_fp": 0,
                "poor_count": 0,
                "needs_review_count": 0,
            }
        c = categories[cat]
        c["rule_count"] += 1
        c["total_alerts"] += r["total_alerts"]
        c["total_fp"] += r["false_positive_count"]
        if r["quality_band"] == "POOR":
            c["poor_count"] += 1
        elif r["quality_band"] == "NEEDS_REVIEW":
            c["needs_review_count"] += 1

    result = []
    for cat_data in categories.values():
        total = cat_data["total_alerts"]
        fp = cat_data["total_fp"]
        cat_data["fp_rate"] = round(fp / total, 4) if total > 0 else 0.0
        result.append(cat_data)

    result.sort(key=lambda x: x["category"])
    return result
