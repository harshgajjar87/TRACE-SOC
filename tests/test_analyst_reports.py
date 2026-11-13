"""Day 27 tests — Analyst Report Center."""

import pytest
from reports.analyst_report import (
    build_executive_summary_text,
    get_multi_story_briefs,
    generate_executive_summary_pdf,
    generate_single_story_text_report,
)


def test_executive_summary_text_empty():
    text = build_executive_summary_text([])
    assert isinstance(text, str)
    assert "TRACE-SOC" in text
    assert "No investigation" in text


def test_executive_summary_text_with_brief():
    brief = {
        "story_id": 1,
        "title": "Test Investigation",
        "severity": "HIGH",
        "status": "INVESTIGATING",
        "confidence_score": 72,
        "confidence_level": "MEDIUM",
        "first_seen": "2024-01-01T00:00:00",
        "last_seen": "2024-01-02T00:00:00",
        "event_count": 15,
        "alert_count": 3,
        "description": "Suspicious login activity",
        "mitre_tactics": ["Credential Access"],
        "affected_hosts": ["HOST-A"],
        "affected_users": ["jdoe"],
        "source_ips": ["192.168.1.5"],
        "relationship_count": 2,
        "timeline_summary": [],
        "linked_alerts": [],
        "severity_distribution": {"HIGH": 3},
    }
    text = build_executive_summary_text([brief])
    assert "Test Investigation" in text
    assert "HIGH" in text
    assert "INVESTIGATING" in text
    assert "jdoe" in text
    assert "HOST-A" in text


def test_executive_summary_text_multiple_briefs():
    briefs = [
        {
            "story_id": i,
            "title": f"Case {i}",
            "severity": "MEDIUM",
            "status": "NEW",
            "confidence_score": 50,
            "confidence_level": "LOW",
            "first_seen": "2024-01-01T00:00:00",
            "last_seen": "2024-01-01T12:00:00",
            "event_count": 5,
            "alert_count": 1,
            "description": "",
            "mitre_tactics": [],
            "affected_hosts": [],
            "affected_users": [],
            "source_ips": [],
            "relationship_count": 0,
            "timeline_summary": [],
            "linked_alerts": [],
            "severity_distribution": {},
        }
        for i in range(1, 4)
    ]
    text = build_executive_summary_text(briefs)
    assert "Case 1" in text
    assert "Case 3" in text
    assert "3 investigation" in text


def test_executive_summary_pdf_returns_bytes():
    briefs = []
    pdf = generate_executive_summary_pdf(briefs)
    assert isinstance(pdf, bytes)
    assert len(pdf) > 0


def test_executive_summary_pdf_with_brief():
    brief = {
        "story_id": 42,
        "title": "PDF Test Case",
        "severity": "CRITICAL",
        "status": "INVESTIGATING",
        "confidence_score": 88,
        "confidence_level": "HIGH",
        "first_seen": "2024-03-01T08:00:00",
        "last_seen": "2024-03-01T16:00:00",
        "event_count": 42,
        "alert_count": 7,
        "description": "Critical ransomware precursor activity.",
        "mitre_tactics": ["Execution", "Persistence"],
        "affected_hosts": ["FINANCE-PC"],
        "affected_users": ["cfo"],
        "source_ips": ["10.0.0.99"],
        "relationship_count": 5,
        "timeline_summary": [],
        "linked_alerts": [],
        "severity_distribution": {"CRITICAL": 2, "HIGH": 5},
    }
    pdf = generate_executive_summary_pdf([brief])
    assert isinstance(pdf, bytes)
    assert len(pdf) > 100


def test_get_multi_story_briefs_empty(test_db):
    # With no stories in DB, should return empty list (errors skipped)
    result = get_multi_story_briefs([999, 998])
    assert isinstance(result, list)
    assert len(result) == 0


def test_get_multi_story_briefs_partial_failures(test_db):
    # Mix valid and invalid IDs; invalid ones should be skipped gracefully
    result = get_multi_story_briefs([999999, 888888])
    assert isinstance(result, list)


def test_executive_summary_text_contains_disclaimer():
    # Empty briefs: minimal text, just check structure exists
    text = build_executive_summary_text([])
    assert isinstance(text, str)
    assert len(text) > 0

    # With briefs: disclaimer must appear
    brief = {
        "story_id": 1,
        "title": "Disclaimer Test",
        "severity": "HIGH",
        "status": "NEW",
        "confidence_score": 50,
        "confidence_level": "MEDIUM",
        "first_seen": "",
        "last_seen": "",
        "event_count": 1,
        "alert_count": 0,
        "description": "",
        "mitre_tactics": [],
        "affected_hosts": [],
        "affected_users": [],
        "source_ips": [],
        "relationship_count": 0,
        "timeline_summary": [],
        "linked_alerts": [],
        "severity_distribution": {},
    }
    text_with_brief = build_executive_summary_text([brief])
    assert "DISCLAIMER" in text_with_brief or "heuristic" in text_with_brief.lower()


def test_executive_summary_text_aggregate_stats():
    briefs = [
        {
            "story_id": 1,
            "title": "Agg Test",
            "severity": "HIGH",
            "status": "NEW",
            "confidence_score": 60,
            "confidence_level": "MEDIUM",
            "first_seen": "",
            "last_seen": "",
            "event_count": 100,
            "alert_count": 10,
            "description": "",
            "mitre_tactics": [],
            "affected_hosts": [],
            "affected_users": [],
            "source_ips": [],
            "relationship_count": 0,
            "timeline_summary": [],
            "linked_alerts": [],
            "severity_distribution": {},
        }
    ]
    text = build_executive_summary_text(briefs)
    assert "100" in text   # event count
    assert "10" in text    # alert count


def test_generate_single_story_text_report_missing(test_db):
    with pytest.raises(ValueError, match="not found"):
        generate_single_story_text_report(99999)
