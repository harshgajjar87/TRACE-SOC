"""Generate a portable PDF investigation report from stored TRACE-SOC records."""
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

from investigation.timeline import get_story_timeline
from investigation.investigation_queries import get_investigation
from investigation.evidence import get_story_evidence, verify_raw_event_integrity


def generate_investigation_pdf(story_id: int) -> bytes:
    investigation = get_investigation(int(story_id))
    story = investigation["story"]
    timeline = investigation.get("timeline", [])
    alerts = investigation.get("alerts", [])
    evidence = get_story_evidence(int(story_id))

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=17*mm, leftMargin=17*mm,
                            topMargin=17*mm, bottomMargin=17*mm, title=f"TRACE-SOC Investigation {story_id}")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER,
                              textColor=colors.HexColor("#12304A"), spaceAfter=8))
    styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7.5, leading=9))
    story_flow = [Paragraph("TRACE-SOC Investigation Report", styles["ReportTitle"]),
                  Paragraph(f"Investigation #{int(story_id)} — {escape(str(story.get('title') or 'Untitled'))}", styles["Heading2"]),
                  Paragraph("This report summarizes records stored by TRACE-SOC. Correlation indicates analytical relationships and does not by itself prove malicious activity.", styles["BodyText"]), Spacer(1, 8)]

    summary = [
        ["Severity", str(story.get("severity") or "INFO"), "Status", str(story.get("status") or "NEW")],
        ["Hostname", str(story.get("hostname") or "Unknown"), "Username", str(story.get("username") or "Unknown")],
        ["Source IP", str(story.get("source_ip") or "Unknown"), "Confidence", f"{story.get('confidence_score', 0)} / {story.get('confidence_level', 'LOW')}"],
        ["First seen", str(story.get("first_seen") or "Unknown"), "Last seen", str(story.get("last_seen") or "Unknown")],
        ["Events", str(story.get("event_count", 0)), "Alerts", str(story.get("alert_count", 0))],
    ]
    table=Table(summary,colWidths=[24*mm,55*mm,24*mm,55*mm])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#E8EEF4")),
                               ("BACKGROUND",(2,0),(2,-1),colors.HexColor("#E8EEF4")),
                               ("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#B8C4D0")),
                               ("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"TOP"),
                               ("LEFTPADDING",(0,0),(-1,-1),5),("RIGHTPADDING",(0,0),(-1,-1),5),
                               ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
    story_flow += [table, Spacer(1, 12), Paragraph("Chronological Event Timeline", styles["Heading2"])]
    timeline_data=[["Time","Event","Type","Host / User","Source IP","Raw ID"]]
    for item in timeline:
        timeline_data.append([Paragraph(escape(str(item.get("timestamp_utc") or "-")),styles["SmallCell"]),
            str(item.get("event_id") or "-"),Paragraph(escape(str(item.get("event_type") or "-")),styles["SmallCell"]),
            Paragraph(escape(f"{item.get('hostname') or '-'} / {item.get('username') or '-'}"),styles["SmallCell"]),
            str(item.get("source_ip") or "-"),str(item.get("raw_event_id") or "-")])
    if len(timeline_data)==1: timeline_data.append(["No linked events","","","","",""])
    t=Table(timeline_data,repeatRows=1,colWidths=[37*mm,16*mm,28*mm,43*mm,29*mm,17*mm])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#12304A")),
                           ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#CBD5E1")),
                           ("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP"),
                           ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#F4F7FA")])]))
    story_flow += [t, Spacer(1, 12), Paragraph("Linked Detection Alerts", styles["Heading2"])]
    alert_data=[["Rule","Name","Severity","Status","Event count"]]
    for a in alerts:
        alert_data.append([str(a.get("rule_id") or "-"),Paragraph(escape(str(a.get("rule_name") or "-")),styles["SmallCell"]),
                           str(a.get("severity") or "-"),str(a.get("status") or "-"),str(a.get("event_count") or 0)])
    if len(alert_data)==1: alert_data.append(["No linked alerts","","","",""])
    at=Table(alert_data,repeatRows=1,colWidths=[20*mm,75*mm,25*mm,30*mm,20*mm])
    at.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#12304A")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                            ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#CBD5E1")),("FONTSIZE",(0,0),(-1,-1),7),
                            ("VALIGN",(0,0),(-1,-1),"TOP")]))
    story_flow += [at, Spacer(1, 12), Paragraph("Evidence Integrity References", styles["Heading2"])]
    ev_data=[["Raw ID","Source file","Recorded SHA-256","Verification"]]
    for ev in evidence:
        check=verify_raw_event_integrity(ev["raw_event_id"])
        ev_data.append([str(ev["raw_event_id"]),Paragraph(escape(str(ev.get("source_file") or "-")),styles["SmallCell"]),
                        Paragraph(escape(str(ev.get("raw_xml_sha256") or "No baseline hash")),styles["SmallCell"]),check["status"]])
    if len(ev_data)==1: ev_data.append(["No linked evidence","","",""])
    et=Table(ev_data,repeatRows=1,colWidths=[16*mm,42*mm,93*mm,19*mm])
    et.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#12304A")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                            ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#CBD5E1")),("FONTSIZE",(0,0),(-1,-1),7),
                            ("VALIGN",(0,0),(-1,-1),"TOP")]))
    story_flow += [et, Spacer(1, 10), Paragraph("Integrity note: VERIFIED means the current stored XML blob matches its recorded SHA-256 baseline. It does not independently establish the authenticity of the original source or acquisition process.", styles["Italic"])]
    doc.build(story_flow)
    return buffer.getvalue()
