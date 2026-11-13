"""TRACE-SOC dark SOC analyst workspace. Run: streamlit run dashboard/app.py"""

from __future__ import annotations

import sys

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:

    sys.path.insert(0, str(ROOT))

try:

    import streamlit as st

    import plotly.express as px

except ImportError as exc:

    raise SystemExit("Dashboard dependencies missing. Run: pip install -r requirements.txt") from exc

from database.db import create_tables

from investigation.story_schema import create_story_tables

from dashboard.data_access import (

    ALERT_STATUSES, SEVERITIES, ensure_dashboard_schema,

    get_dashboard_summary, get_alerts, update_alert_status,

    get_alert_status_history, get_stories, search_events,

)

from investigation.investigation_queries import get_investigation

from investigation.evidence import get_story_evidence, verify_raw_event_integrity

from reports.pdf_generator import generate_investigation_pdf

from threat_intel.engine import create_threat_intel_schema

from response.engine import create_response_schema

from cases.engine import create_case_schema

from risk.engine import create_risk_schema

from attack.engine import create_attack_schema

from monitoring.engine import create_monitoring_schema

from monitoring.analysis_pipeline import create_analysis_schema

from investigation.chain_of_custody import create_chain_of_custody_schema

from forensics.engine import create_forensics_schema

from threat_intel.correlator import create_ioc_correlation_schema
from dashboard.styles import inject_styles

st.set_page_config(
    page_title="CYFROG | An Intelligent TRACE System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Styles are defined in dashboard/styles.py
inject_styles()

@st.cache_resource

def initialize_database():

    create_tables()

    create_story_tables()

    ensure_dashboard_schema()

    create_threat_intel_schema()

    create_response_schema()

    create_case_schema()

    create_risk_schema()

    create_attack_schema()

    create_monitoring_schema()

    create_analysis_schema()

    create_chain_of_custody_schema()

    create_forensics_schema()

    create_ioc_correlation_schema()

    return True

try:

    initialize_database()

except Exception as exc:

    st.error(f"Database initialization failed: {exc}")

    st.stop()

# ---------------------------------------------------------------------------

# Navigation structure — 5 workspaces, each with their own pages

# ---------------------------------------------------------------------------

WORKSPACES: dict[str, dict] = {
    "Command Center": {
        "icon": "◈",
        "color": "#38bdf8",
        "pages": [
            "Overview",
            "Alert Management",
            "Live Monitoring",
            "Automated Detection",
        ],
    },
    "Threat Intelligence": {
        "icon": "◉",
        "color": "#a78bfa",
        "pages": [
            "Threat Hunting",
            "Threat Intelligence",
            "IOC Correlation",
            "Risk Intelligence",
        ],
    },
    "Investigation & DFIR": {
        "icon": "⌕",
        "color": "#34d399",
        "pages": [
            "Investigations",
            "Forensic Artifacts",
            "Evidence & Integrity",
            "Forensic Timeline",
            "Case Management",
            "Incident Response",
        ],
    },
    "Detection Engineering": {
        "icon": "◎",
        "color": "#fb923c",
        "pages": [
            "Detection Intelligence",
            "Detection Quality",
            "MITRE ATT&CK Coverage",
        ],
    },
    "Reports & Admin": {
        "icon": "▤",
        "color": "#fbbf24",
        "pages": [
            "Analyst Reports",
            "Soc Analytics",
            "System Health",
        ],
    },
}

PAGE_ICONS = {
    "Overview": "◈",
    "Alert Management": "⚑",
    "Live Monitoring": "📡",
    "Automated Detection": "🧠",
    "Threat Hunting": "⌘",
    "Threat Intelligence": "◉",
    "IOC Correlation": "🔗",
    "Risk Intelligence": "🎯",
    "Investigations": "⌕",
    "Forensic Artifacts": "🗂️",
    "Evidence & Integrity": "⬡",
    "Forensic Timeline": "🕒",
    "Case Management": "📁",
    "Incident Response": "🛡️",
    "Detection Intelligence": "◎",
    "Detection Quality": "🎚️",
    "MITRE ATT&CK Coverage": "🗺️",
    "Analyst Reports": "📑",
    "Soc Analytics": "📊",
    "System Health": "💚",
}

# ── Sidebar brand header ──────────────────────────────────────────────────
st.sidebar.markdown("""
<div style="padding:10px 4px 16px;">
  <div style="display:flex;align-items:center;gap:13px;">
    <div style="font-size:32px;line-height:1;">🛡️</div>
    <div>
      <div style="font-size:1.35rem;font-weight:800;color:#edf6ff;
                  letter-spacing:.02em;line-height:1.2;">CYFROG</div>
      <div style="font-size:.72rem;color:#7dd3fc;letter-spacing:.14em;
                  font-weight:700;margin-top:3px;">AN INTELLIGENT TRACE SYSTEM</div>
    </div>
  </div>
  <div style="font-size:.82rem;color:#637e9e;margin-top:10px;line-height:1.55;">
    Security Operations &amp; Digital Forensics
  </div>
</div>
<div class="ws-divider"></div>
""", unsafe_allow_html=True)

# ── Workspace selector ────────────────────────────────────────────────────
st.sidebar.markdown(
    "<div class='ws-section-label'>Workspace</div>",
    unsafe_allow_html=True,
)

workspace_names = list(WORKSPACES.keys())

# Persist the active workspace in session state
if "active_workspace" not in st.session_state:
    st.session_state["active_workspace"] = workspace_names[0]

for ws_name in workspace_names:
    ws = WORKSPACES[ws_name]
    is_active = st.session_state["active_workspace"] == ws_name
    page_count = len(ws["pages"])
    # Collapsible visual cue: ▾ when open, ▸ when closed
    arrow = "▾" if is_active else "▸"
    label = f"{ws['icon']}  {ws_name}  {arrow}"
    btn_key = f"ws_btn_{ws_name}"
    btn_type = "primary" if is_active else "secondary"

    if st.sidebar.button(label, key=btn_key, type=btn_type, use_container_width=True):
        if is_active:
            # Keep it open and jump to first page
            target_page = ws["pages"][0]
            st.session_state["active_page"] = target_page
            st.session_state[f"module_radio_{ws_name}"] = target_page
        else:
            st.session_state["active_workspace"] = ws_name
            target_page = ws["pages"][0]
            st.session_state["active_page"] = target_page
            st.session_state[f"module_radio_{ws_name}"] = target_page
        st.rerun()

    # ── Module list — only shown for the active workspace ──────────────
    if is_active:
        st.sidebar.markdown(
            f"<div style='margin:4px 0 2px 6px;font-size:.72rem;color:{ws['color']};"
            f"letter-spacing:.14em;font-weight:700;text-transform:uppercase;'>"
            f"{page_count} modules</div>",
            unsafe_allow_html=True,
        )

        ws_pages = ws["pages"]

        # Synchronize active module with remembered state
        radio_key = f"module_radio_{ws_name}"
        if radio_key not in st.session_state or st.session_state[radio_key] not in ws_pages:
            st.session_state[radio_key] = ws_pages[0]

        page = st.sidebar.radio(
            f"module_{ws_name}",
            ws_pages,
            format_func=lambda p: f"{PAGE_ICONS.get(p, '·')}  {p}",
            label_visibility="collapsed",
            key=radio_key,
        )
        st.session_state["active_page"] = page

        st.sidebar.markdown("<div class='ws-divider'></div>", unsafe_allow_html=True)

# resolve active workspace and page for use in page functions
active_ws_name = st.session_state["active_workspace"]
active_ws = WORKSPACES[active_ws_name]
if "active_page" not in st.session_state or st.session_state["active_page"] not in active_ws["pages"]:
    st.session_state["active_page"] = active_ws["pages"][0]
page = st.session_state["active_page"]

# ── Status / footer ────────────────────────────────────────────────────────
st.sidebar.markdown(
    "<div style='margin-top:8px;'>"
    "<span class='status-pill'>● LOCAL DATABASE</span>"
    "</div>",
    unsafe_allow_html=True,
)
st.sidebar.caption("CYFROG · An Intelligent TRACE System")
st.sidebar.caption("Data source: local SQLite")

def page_header(title: str, subtitle: str, section: str | None = None):

    # Build breadcrumb: "Workspace  /  Page" if section not supplied explicitly

    if section is None:

        section = f"{active_ws_name.upper()}  /  {page.upper()}"

    left, right = st.columns([5, 1])

    with left:

        st.markdown(

            f"<div class='top-banner'><div class='eyebrow'>{section}</div>"

            f"<div class='banner-title'>{title}</div><div class='banner-sub'>{subtitle}</div></div>",

            unsafe_allow_html=True,

        )

    with right:

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        if st.button("↻ Refresh", use_container_width=True):

            st.rerun()

def section_title(title: str, hint: str | None = None):

    st.markdown(f"<div class='section-kicker'>{title}</div>", unsafe_allow_html=True)

    if hint:

        st.caption(hint)

def metric_card(label: str, value, foot: str = "", accent: str = "#38bdf8"):

    st.markdown(

        f"<div class='metric-card'><div class='metric-label'>{label}</div>"

        f"<div class='metric-value' style='color:{accent};'>{value}</div>"

        f"<div class='metric-foot'>{foot}</div></div>", unsafe_allow_html=True,

    )

def show_table(rows, empty_message="No records found."):

    if rows:

        st.dataframe(rows, use_container_width=True, hide_index=True)

    else:

        st.info(empty_message)

def style_chart(fig, height=310):

    fig.update_layout(

        template="plotly_dark", height=height, paper_bgcolor="rgba(0,0,0,0)",

        plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#b9c9dc", family="Inter, Segoe UI, sans-serif"),

        title=dict(font=dict(size=14, color="#e7f1fc")),

        margin=dict(l=12, r=12, t=48, b=12), legend=dict(font=dict(color="#a9bdd3")),

        xaxis=dict(gridcolor="rgba(119,148,181,.13)", zerolinecolor="rgba(119,148,181,.18)"),

        yaxis=dict(gridcolor="rgba(119,148,181,.13)", zerolinecolor="rgba(119,148,181,.18)"),

    )

    return fig

def overview():

    data = get_dashboard_summary()

    counts = data["counts"]

    page_header("Security Overview", "A consolidated view of endpoint telemetry, detections and investigations.", "COMMAND CENTER  /  OVERVIEW")

    st.markdown("<div class='section-kicker'>ENVIRONMENT SNAPSHOT</div>", unsafe_allow_html=True)

    cards = [

        ("NORMALIZED EVENTS", counts.get("total_events", 0), "Events in local store", "#67d5f5"),

        ("DETECTION ALERTS", counts.get("total_alerts", 0), "All recorded detections", "#a5b4fc"),

        ("OPEN ALERTS", counts.get("open_alerts", 0), "New or investigating", "#fbbf24"),

        ("CRITICAL OPEN", counts.get("critical_alerts", 0), "Require priority review", "#fb7185"),

        ("ATTACK STORIES", counts.get("total_stories", 0), "Correlated investigations", "#34d399"),

    ]

    cols = st.columns(5)

    for col, (label, value, foot, accent) in zip(cols, cards):

        with col:

            metric_card(label, f"{value:,}", foot, accent)

    st.write("")

    left, right = st.columns([1.15, 1])

    with left:

        section_title("ALERT SEVERITY", "Distribution of alerts by assigned severity")

        if data["severity"]:

            colors = {"CRITICAL":"#fb7185", "HIGH":"#fb923c", "MEDIUM":"#fbbf24", "LOW":"#38bdf8", "INFO":"#94a3b8"}

            fig = px.bar(data["severity"], x="severity", y="count", color="severity",

                         color_discrete_map=colors, category_orders={"severity":["CRITICAL","HIGH","MEDIUM","LOW","INFO"]})

            fig.update_traces(marker_line_width=0, hovertemplate="%{x}<br>Alerts: %{y}<extra></extra>")

            st.plotly_chart(style_chart(fig), use_container_width=True, config={"displayModeBar": False})

        else:

            st.info("No alerts have been generated yet.")

    with right:

        section_title("ALERT WORKFLOW", "Current analyst triage status")

        if data["status"]:

            status_colors = {"NEW":"#38bdf8", "INVESTIGATING":"#fbbf24", "RESOLVED":"#34d399", "FALSE_POSITIVE":"#94a3b8"}

            fig = px.pie(data["status"], names="status", values="count", hole=.66, color="status", color_discrete_map=status_colors)

            fig.update_traces(textposition="inside", textinfo="percent", marker=dict(line=dict(color="#0b1524", width=3)))

            st.plotly_chart(style_chart(fig), use_container_width=True, config={"displayModeBar": False})

        else:

            st.info("No alert workflow records yet.")

    st.write("")

    left, right = st.columns([1.15, 1])

    with left:

        section_title("EVENT TELEMETRY", "Most frequently observed normalized event categories")

        if data["event_categories"]:

            fig = px.bar(data["event_categories"], x="count", y="category", orientation="h", color="count",

                         color_continuous_scale=["#164e63", "#0ea5e9", "#67e8f9"])

            fig.update_layout(coloraxis_showscale=False)

            st.plotly_chart(style_chart(fig, 330), use_container_width=True, config={"displayModeBar": False})

        else:

            st.info("No normalized event categories available.")

    with right:

        section_title("RECENT DETECTIONS", "Latest alerts requiring analyst visibility")

        show_table(data["recent_alerts"], "No alerts have been generated yet.")

    st.caption("Metrics reflect records stored in the local CYFROG SQLite database. They are not live endpoint telemetry unless collection is running.")

def alert_management():

    from dashboard.views.alerts import render_alert_management

    render_alert_management()

def investigations():

    page_header("Attack Investigations", "Explore correlated security activity as persistent, evidence-linked cases.", "INVESTIGATIONS  /  CASE EXPLORER")

    f1, f2, f3 = st.columns([1, 1, 2])

    status = f1.selectbox("Story status", ["ALL", *ALERT_STATUSES], key="story_status")

    severity = f2.selectbox("Story severity", ["ALL", *SEVERITIES], key="story_severity")

    search = f3.text_input("Search title, host, username or source IP", key="story_search")

    stories = get_stories(status=status, severity=severity, search=search)

    show_table([{k:s.get(k) for k in ["id","title","severity","status","hostname","username","source_ip","event_count","alert_count","confidence_score","confidence_level","first_seen","last_seen"]} for s in stories])

    if stories:

        selected = st.selectbox("Open investigation", [s["id"] for s in stories], format_func=lambda x:f"#{x} — {next(s['title'] for s in stories if s['id']==x)}")

        result = get_investigation(selected)

        if not result or not result.get("story"):

            st.warning("Investigation details could not be loaded.")

            return

        story = result["story"]

        st.markdown(f"### CASE #{selected} · {story['title']}")

        st.write(story.get("description") or "No description")

        st.info(f"Correlation strength: {story.get('confidence_score',0)} / {story.get('confidence_level','LOW')} — heuristic relationship strength, not attack probability.")

        section_title("CHRONOLOGICAL TIMELINE")

        show_table([{k:e.get(k) for k in ["timestamp_utc","normalized_event_id","event_id","event_type","hostname","username","source_ip","destination_ip","image","command_line","rule_id","rule_name","alert_severity","raw_event_id"]} for e in result.get("timeline",[])])

        with st.expander("CORRELATION RELATIONSHIPS"):

            show_table(result.get("relationships", []), "No relationship edges stored.")

        with st.expander("LINKED ALERTS"):

            show_table([{k:a.get(k) for k in ["id","rule_id","rule_name","severity","status","created_at_utc"]} for a in result.get("alerts",[])])

def threat_hunting():

    from dashboard.views.threat_hunting import render_threat_hunting

    render_threat_hunting()

def evidence_page():

    page_header("Evidence & Integrity", "Retrieve linked evidence and verify stored XML against its recorded SHA-256 baseline.", "DFIR  /  EVIDENCE VAULT")

    story_id = st.number_input("Investigation story ID", min_value=1, step=1)

    if st.button("Load linked evidence", type="primary"):

        try:

            st.session_state["evidence_records"] = get_story_evidence(int(story_id))

        except Exception as exc:

            st.error(str(exc))

    records = st.session_state.get("evidence_records", [])

    if records:

        checks = []

        for item in records:

            check = verify_raw_event_integrity(item["raw_event_id"])

            checks.append({"raw_event_id":item["raw_event_id"], "source_file":item.get("source_file"),

                           "raw_xml_sha256":item.get("raw_xml_sha256"), "status":check["status"]})

        show_table(checks)

        st.caption("VERIFIED means the stored XML blob matches its recorded hash baseline; it does not independently prove original evidence authenticity.")

    elif "evidence_records" in st.session_state:

        st.info("No linked evidence records found for this story.")

def detection_intelligence():

    page_header("Detection Intelligence", "Understand configured rule coverage without overstating what the engine can detect.", "DETECTION  /  COVERAGE")

    from detection.rules import DETECTION_RULES

    from detection.coverage import DETECTION_COVERAGE

    rules = DETECTION_RULES

    metric_card("CONFIGURED DETECTION RULES", len(rules), "Rules defined in the custom engine", "#67d5f5")

    by_category = {}

    for rule in rules:

        category = rule.get("category", "uncategorized")

        by_category[category] = by_category.get(category, 0) + 1

    if by_category:

        fig = px.bar(x=list(by_category), y=list(by_category.values()), labels={"x":"Category", "y":"Rules"}, color=list(by_category.values()), color_continuous_scale=["#164e63", "#0ea5e9", "#67e8f9"])

        fig.update_layout(coloraxis_showscale=False)

        st.plotly_chart(style_chart(fig, 350), use_container_width=True, config={"displayModeBar":False})

    show_table([{k:r.get(k) for k in ["rule_id","name","category","rule_type","severity","mitre_tactic","mitre_technique"]} for r in rules])

    st.info("Configured rules describe intended detection logic. This view does not claim every attack technique is covered or that every rule has fired in production.")

    with st.expander("VIEW COVERAGE REGISTRY"):

        st.json(DETECTION_COVERAGE)

def reports_page():

    page_header("Investigation Reports", "Generate portable PDF case summaries for review, handover and academic demonstration.", "DFIR  /  REPORTING")

    stories = get_stories(limit=500)

    if not stories:

        st.info("No investigation stories are available to report.")

        return

    selected = st.selectbox("Select investigation", [s["id"] for s in stories], format_func=lambda x:f"#{x} — {next(s['title'] for s in stories if s['id']==x)}")

    st.caption("The PDF includes the story summary, chronological event timeline, linked alerts and evidence hash verification references.")

    if st.button("Generate PDF report", type="primary"):

        try:

            pdf = generate_investigation_pdf(selected)

            st.download_button("⬇ Download investigation PDF", data=pdf, file_name=f"TRACE-SOC-investigation-{selected}.pdf", mime="application/pdf")

        except Exception as exc:

            st.error(f"Report generation failed: {exc}")

def threat_intelligence():

    from dashboard.views.threat_intelligence import (

        render_threat_intelligence

    )

    render_threat_intelligence()

def incident_response():

    from dashboard.views.incident_response import render_incident_response

    render_incident_response()

def case_management():

    from dashboard.views.case_management import render_case_management

    render_case_management()

def soc_analytics():

    from dashboard.views.soc_analytics import render_soc_analytics

    render_soc_analytics()

def risk_intelligence():

    from dashboard.views.risk_intelligence import render_risk_intelligence

    render_risk_intelligence()

def attack_coverage():

    from dashboard.views.attack_coverage import render_attack_coverage

    render_attack_coverage()

def live_monitoring():

    from dashboard.views.live_monitoring import render_live_monitoring

    render_live_monitoring()

def automated_detection():

    from dashboard.views.detection_monitor import render_detection_monitor

    render_detection_monitor()

def evidence_page():

    from dashboard.views.evidence import render_evidence

    render_evidence()

def forensic_artifacts():

    from dashboard.views.forensic_artifacts import render_forensic_artifacts

    render_forensic_artifacts()

def forensic_timeline():

    from dashboard.views.forensic_timeline import render_forensic_timeline

    render_forensic_timeline()

def detection_quality():

    from dashboard.views.detection_quality import render_detection_quality

    render_detection_quality()

def ioc_correlation():

    from dashboard.views.ioc_correlation import render_ioc_correlation

    render_ioc_correlation()

def analyst_reports():

    from dashboard.views.analyst_reports import render_analyst_reports

    render_analyst_reports()

def system_health():

    from dashboard.views.system_health import render_system_health

    render_system_health()

PAGE_FUNCTIONS = {

    # Command Center

    "Overview": overview,

    "Alert Management": alert_management,

    "Live Monitoring": live_monitoring,

    "Automated Detection": automated_detection,

    # Threat Intelligence

    "Threat Hunting": threat_hunting,

    "Threat Intelligence": threat_intelligence,

    "IOC Correlation": ioc_correlation,

    "Risk Intelligence": risk_intelligence,

    # Investigation & DFIR

    "Investigations": investigations,

    "Forensic Artifacts": forensic_artifacts,

    "Evidence & Integrity": evidence_page,

    "Forensic Timeline": forensic_timeline,

    "Case Management": case_management,

    "Incident Response": incident_response,

    # Detection Engineering

    "Detection Intelligence": detection_intelligence,

    "Detection Quality": detection_quality,

    "MITRE ATT&CK Coverage": attack_coverage,

    # Reports & Admin

    "Analyst Reports": analyst_reports,

    "Soc Analytics": soc_analytics,

    "System Health": system_health,

}

PAGE_FUNCTIONS[page]()

