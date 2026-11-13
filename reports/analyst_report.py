"""
TRACE-SOC Day 27 — Analyst Report Center

Multi-story exports, executive summary generation and formatted
investigation briefs. Extends the existing PDF infrastructure with
batch exports and an executive summary mode.

All reports are generated in-memory and returned as bytes for
Streamlit download buttons. No files are written to disk here.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import Any

from database.db import get_connection
from investigation.investigation_queries import get_investigation
from dashboard.data_access import get_stories


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dict_rows(rows):
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def get_story_brief(story_id: int) -> dict:
    """
    Return a report-ready dict for one investigation story.
    Combines the investigation query with risk and alert data.
    """
    result = get_investigation(story_id)
    if not result or not result.get("story"):
        raise ValueError(f"Investigation story {story_id} not found.")

    story = result["story"]
    timeline = result.get("timeline", [])
    alerts = result.get("alerts", [])
    relationships = result.get("relationships", [])

    # Risk metrics: count severity distribution of linked alerts
    sev_dist: dict[str, int] = {}
    for alert in alerts:
        sev = str(alert.get("severity") or "UNKNOWN").upper()
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

    # MITRE tactics seen in this investigation
    tactics = sorted({
        str(e.get("mitre_tactic") or e.get("rule_name") or "")
        for e in timeline
        if e.get("mitre_tactic") or e.get("rule_name")
    } - {""})

    # Unique hosts and users
    hosts = sorted({str(e.get("hostname") or "") for e in timeline} - {""})
    users = sorted({str(e.get("username") or "") for e in timeline} - {""})
    source_ips = sorted({str(e.get("source_ip") or "") for e in timeline} - {""})

    return {
        "story_id": story_id,
        "title": story.get("title", ""),
        "description": story.get("description", ""),
        "severity": story.get("severity", ""),
        "status": story.get("status", ""),
        "confidence_score": story.get("confidence_score", 0),
        "confidence_level": story.get("confidence_level", ""),
        "first_seen": story.get("first_seen", ""),
        "last_seen": story.get("last_seen", ""),
        "event_count": story.get("event_count", 0),
        "alert_count": story.get("alert_count", 0),
        "hostname": story.get("hostname", ""),
        "username": story.get("username", ""),
        "source_ip": story.get("source_ip", ""),
        "severity_distribution": sev_dist,
        "mitre_tactics": tactics,
        "affected_hosts": hosts,
        "affected_users": users,
        "source_ips": source_ips,
        "relationship_count": len(relationships),
        "timeline_summary": timeline[:5],  # first 5 events for the brief
        "linked_alerts": alerts,
    }


def get_multi_story_briefs(story_ids: list[int]) -> list[dict]:
    """Return briefs for multiple stories, skipping any that fail."""
    briefs = []
    for sid in story_ids:
        try:
            briefs.append(get_story_brief(sid))
        except (ValueError, Exception):
            pass
    return briefs


def get_all_open_stories() -> list[dict]:
    """Convenience: return briefs for all NEW or INVESTIGATING stories."""
    stories = get_stories(status="ALL", limit=1000)
    open_ids = [
        s["id"] for s in stories
        if str(s.get("status", "")).upper() in ("NEW", "INVESTIGATING")
    ]
    return get_multi_story_briefs(open_ids)


# ---------------------------------------------------------------------------
# Text / plain-text report builder
# ---------------------------------------------------------------------------

_SEP = "─" * 72


def _fmt_line(label: str, value: Any, width: int = 24) -> str:
    return f"  {label:<{width}}: {value}"


def build_executive_summary_text(briefs: list[dict]) -> str:
    """
    Build a plain-text executive summary covering multiple investigations.
    Suitable for email body or plain-text export.
    """
    lines = [
        "TRACE-SOC  |  EXECUTIVE SUMMARY",
        f"Generated : {_utc_now()}",
        f"Scope     : {len(briefs)} investigation(s)",
        _SEP,
        "",
    ]

    if not briefs:
        lines.append("No investigation stories available for this report.")
        return "\n".join(lines)

    # Aggregate statistics
    total_events = sum(b.get("event_count", 0) for b in briefs)
    total_alerts = sum(b.get("alert_count", 0) for b in briefs)
    sev_counts: dict[str, int] = {}
    for b in briefs:
        s = str(b.get("severity") or "UNKNOWN").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines += [
        "  AGGREGATE STATISTICS",
        _fmt_line("Total investigations", len(briefs)),
        _fmt_line("Total events", total_events),
        _fmt_line("Total linked alerts", total_alerts),
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev_counts.get(sev):
            lines.append(_fmt_line(f"  {sev}", sev_counts[sev]))

    lines += ["", _SEP, ""]

    for idx, brief in enumerate(briefs, 1):
        lines += [
            f"  INVESTIGATION {idx} of {len(briefs)}",
            _fmt_line("ID", brief["story_id"]),
            _fmt_line("Title", brief["title"]),
            _fmt_line("Severity", brief["severity"]),
            _fmt_line("Status", brief["status"]),
            _fmt_line("Confidence", f"{brief['confidence_score']} ({brief['confidence_level']})"),
            _fmt_line("Period", f"{brief['first_seen']} → {brief['last_seen']}"),
            _fmt_line("Events / Alerts", f"{brief['event_count']} / {brief['alert_count']}"),
        ]

        if brief["affected_hosts"]:
            lines.append(_fmt_line("Hosts", ", ".join(brief["affected_hosts"][:5])))
        if brief["affected_users"]:
            lines.append(_fmt_line("Users", ", ".join(brief["affected_users"][:5])))
        if brief["source_ips"]:
            lines.append(_fmt_line("Source IPs", ", ".join(brief["source_ips"][:5])))
        if brief["mitre_tactics"]:
            lines.append(_fmt_line("MITRE Tactics", ", ".join(brief["mitre_tactics"][:6])))

        if brief.get("timeline_summary"):
            lines += ["", "    TIMELINE EXCERPT (first 5 events):"]
            for ev in brief["timeline_summary"]:
                ts = ev.get("timestamp_utc", "")[:19].replace("T", " ")
                evid = ev.get("event_id", "")
                host = ev.get("hostname", "")
                user = ev.get("username", "")
                img = ev.get("image", "")
                lines.append(f"      {ts}  EID:{evid:<6}  {host:<20}  {user:<16}  {img}")

        lines += ["", _SEP, ""]

    lines += [
        "  DISCLAIMER",
        "  Confidence scores are heuristic relationship-strength indicators.",
        "  They are not statistical proof that an attack occurred.",
        "  All findings require analyst review before action.",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PDF report builder (uses reportlab if available)
# ---------------------------------------------------------------------------

def generate_executive_summary_pdf(briefs: list[dict]) -> bytes:
    """
    Return a PDF executive summary as bytes.
    Falls back gracefully if reportlab is unavailable.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer,
            Table, TableStyle, HRFlowable,
        )
        from reportlab.lib import colors as rl_colors

    except ImportError:
        # Return the text version as UTF-8 bytes if reportlab is missing
        text = build_executive_summary_text(briefs)
        return text.encode("utf-8")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="TRACE-SOC Executive Summary",
        author="TRACE-SOC",
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                        textColor=rl_colors.HexColor("#1e40af"), fontSize=16)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                        textColor=rl_colors.HexColor("#1d4ed8"), fontSize=12)
    normal = styles["Normal"]
    small = ParagraphStyle("Small", parent=normal, fontSize=8)

    SEV_COLORS = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#2563eb",
        "INFO": "#64748b",
    }

    story_elements = []

    story_elements.append(Paragraph("TRACE-SOC | Executive Summary", h1))
    story_elements.append(Paragraph(f"Generated: {_utc_now()}", small))
    story_elements.append(Spacer(1, 0.4 * cm))
    story_elements.append(HRFlowable(width="100%", thickness=1,
                                      color=rl_colors.HexColor("#93c5fd")))
    story_elements.append(Spacer(1, 0.4 * cm))

    if not briefs:
        story_elements.append(Paragraph("No investigation stories available.", normal))
    else:
        # Aggregate table
        total_events = sum(b.get("event_count", 0) for b in briefs)
        total_alerts = sum(b.get("alert_count", 0) for b in briefs)
        agg_data = [
            ["Metric", "Value"],
            ["Investigations", str(len(briefs))],
            ["Total Events", str(total_events)],
            ["Total Alerts", str(total_alerts)],
        ]
        agg_table = Table(agg_data, colWidths=[8 * cm, 6 * cm])
        agg_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#93c5fd")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [rl_colors.HexColor("#f0f9ff"), rl_colors.white]),
        ]))
        story_elements.append(agg_table)
        story_elements.append(Spacer(1, 0.6 * cm))

        for brief in briefs:
            sev = str(brief.get("severity", "INFO")).upper()
            sev_hex = SEV_COLORS.get(sev, "#64748b").lstrip("#")
            sev_color = rl_colors.HexColor(f"#{sev_hex}")
            title_text = (
                f"<font color='#{sev_hex}'>"
                f"[{sev}]</font>  #{brief['story_id']} – {brief['title']}"
            )
            story_elements.append(Paragraph(title_text, h2))

            meta = [
                ["Status", brief.get("status", "")],
                ["Confidence", f"{brief['confidence_score']} ({brief['confidence_level']})"],
                ["Period", f"{brief['first_seen']} → {brief['last_seen']}"],
                ["Events", str(brief.get("event_count", 0))],
                ["Alerts", str(brief.get("alert_count", 0))],
                ["Hosts", ", ".join(brief.get("affected_hosts", [])[:4]) or "—"],
                ["Users", ", ".join(brief.get("affected_users", [])[:4]) or "—"],
                ["Source IPs", ", ".join(brief.get("source_ips", [])[:4]) or "—"],
                ["MITRE Tactics", ", ".join(brief.get("mitre_tactics", [])[:6]) or "—"],
            ]
            meta_table = Table(meta, colWidths=[5 * cm, 11 * cm])
            meta_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, rl_colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (0, -1), rl_colors.HexColor("#f1f5f9")),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                 [rl_colors.HexColor("#f8fafc"), rl_colors.white]),
            ]))
            story_elements.append(meta_table)

            if brief.get("description"):
                story_elements.append(Spacer(1, 0.2 * cm))
                story_elements.append(Paragraph(brief["description"], small))

            story_elements.append(Spacer(1, 0.6 * cm))
            story_elements.append(HRFlowable(width="100%", thickness=0.5,
                                              color=rl_colors.HexColor("#e2e8f0")))
            story_elements.append(Spacer(1, 0.4 * cm))

    # Disclaimer
    story_elements.append(Paragraph(
        "<i>Confidence scores are heuristic indicators. "
        "All findings require analyst review before action.</i>",
        small,
    ))

    doc.build(story_elements)
    return buffer.getvalue()


def generate_single_story_text_report(story_id: int) -> bytes:
    """Generate a plain-text detailed report for one investigation as bytes."""
    brief = get_story_brief(story_id)
    text = build_executive_summary_text([brief])
    return text.encode("utf-8")
