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

st.set_page_config(
    page_title="TRACE-SOC | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# The Streamlit theme is also configured in .streamlit/config.toml.
st.markdown(r"""
<style>
:root {
  --bg: #080f1c; --panel: #101b2b; --panel2: #142238;
  --border: #24364f; --muted: #91a4bd; --text: #e8f0fa;
  --blue: #38bdf8; --cyan: #22d3ee; --green: #34d399;
  --amber: #fbbf24; --orange: #fb923c; --red: #fb7185;
}
html, body, [data-testid="stAppViewContainer"] { background: var(--bg); }
[data-testid="stHeader"] { background: rgba(8,15,28,.92); }
[data-testid="stAppViewContainer"] > .main { background: var(--bg); }
.block-container { max-width: 1600px; padding-top: 1.35rem; padding-bottom: 3rem; }
[data-testid="stSidebar"] { background: #0b1524; border-right: 1px solid var(--border); }
[data-testid="stSidebar"] > div:first-child { padding-top: 1.4rem; }
[data-testid="stSidebar"] [data-testid="stRadio"] label { color: #b8c7da; font-size: .92rem; }
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover { color: #fff; }
[data-testid="stMarkdownContainer"] p, [data-testid="stMarkdownContainer"] li { color: #c8d5e5; }
h1,h2,h3,h4 { color: var(--text) !important; letter-spacing: -.025em; }
[data-testid="stCaptionContainer"] { color: var(--muted); }
hr { border-color: var(--border); }
.metric-card { background: linear-gradient(145deg,#14243a,#0e1929); border: 1px solid #263b57;
  border-radius: 13px; padding: 16px 18px; min-height: 112px; box-shadow: 0 8px 24px rgba(0,0,0,.16); }
.metric-label { color: #9db0c8; font-size: .78rem; text-transform: uppercase; letter-spacing: .08em; font-weight: 650; }
.metric-value { color: #f1f7ff; font-size: 2rem; font-weight: 750; line-height: 1.25; margin-top: 8px; }
.metric-foot { color: #7188a5; font-size: .72rem; margin-top: 3px; }
.top-banner { background: linear-gradient(105deg,#10243b,#102b3d 58%,#12233b); border: 1px solid #294561;
  border-radius: 16px; padding: 20px 24px; margin-bottom: 20px; }
.eyebrow { color: #67d6f4; font-size: .72rem; font-weight: 750; letter-spacing: .16em; text-transform: uppercase; }
.banner-title { color: #f1f7ff; font-size: 1.75rem; font-weight: 760; margin-top: 4px; }
.banner-sub { color: #a9bdd3; font-size: .88rem; margin-top: 5px; }
.section-kicker { color: #7dd3fc; text-transform: uppercase; letter-spacing: .13em; font-size: .72rem; font-weight: 750; margin: 8px 0 10px; }
.status-pill { display:inline-block; border-radius:999px; padding:4px 10px; font-size:.72rem; font-weight:750; background:#17324a; color:#8be2ff; border:1px solid #28516d; }
div[data-testid="stDataFrame"], div[data-testid="stTable"] { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
[data-testid="stExpander"] { background: #0e1a2a; border: 1px solid var(--border); border-radius: 10px; }
.stButton > button, .stDownloadButton > button { border-radius: 9px; border: 1px solid #2c5877; background: #12314b; color: #e8f7ff; font-weight: 650; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color: #38bdf8; color: #fff; background: #174260; }
.stButton > button[kind="primary"] { background: linear-gradient(90deg,#087eaa,#1263a0); border: 0; }
input, textarea, [data-baseweb="select"] > div { background-color: #101e30 !important; }
label, [data-testid="stWidgetLabel"] p { color: #c4d3e5 !important; }
[data-testid="stAlert"] { border-radius: 10px; }
footer { visibility: hidden; }
#MainMenu { visibility: hidden; }
@media (max-width: 900px) { .block-container { padding-left: 1rem; padding-right: 1rem; } .metric-card { min-height: 96px; } }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def initialize_database():
    create_tables()
    create_story_tables()
    ensure_dashboard_schema()
    return True


try:
    initialize_database()
except Exception as exc:
    st.error(f"Database initialization failed: {exc}")
    st.stop()

PAGES = [
    "Overview", "Alert Management", "Investigations", "Threat Hunting",
    "Evidence & Integrity", "Detection Intelligence", "Reports",
]
PAGE_ICONS = {
    "Overview": "◈", "Alert Management": "⚑", "Investigations": "⌕",
    "Threat Hunting": "⌘", "Evidence & Integrity": "⬡",
    "Detection Intelligence": "◎", "Reports": "▤",
}

st.sidebar.markdown("""
<div style="padding:8px 4px 18px;">
 <div style="display:flex;align-items:center;gap:11px;">
  <div style="font-size:30px;">🛡️</div>
  <div><div style="font-size:1.25rem;font-weight:800;color:#edf6ff;letter-spacing:.02em;">TRACE-SOC</div>
  <div style="font-size:.68rem;color:#7dd3fc;letter-spacing:.12em;font-weight:700;">ANALYST WORKSPACE</div></div>
 </div>
 <div style="font-size:.76rem;color:#8196b0;margin-top:12px;line-height:1.5;">Security Operations<br/> &amp; Digital Forensics</div>
</div>
<div style="height:1px;background:#24364f;margin:0 0 16px;"></div>
<div style="font-size:.68rem;color:#6f88a5;letter-spacing:.15em;font-weight:750;margin-bottom:8px;">WORKSPACE MODULES</div>
""", unsafe_allow_html=True)
page = st.sidebar.radio("Navigate", PAGES, format_func=lambda p: f"{PAGE_ICONS[p]}   {p}", label_visibility="collapsed")
st.sidebar.markdown("<div style='height:1px;background:#24364f;margin:18px 0 12px;'></div>", unsafe_allow_html=True)
st.sidebar.markdown("<span class='status-pill'>● LOCAL DATABASE</span>", unsafe_allow_html=True)
st.sidebar.caption("TRACE-SOC community / academic build")
st.sidebar.caption("Data source: local SQLite")


def page_header(title: str, subtitle: str, section: str = "SECURITY OPERATIONS"):
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
    st.caption("Metrics reflect records stored in the local TRACE-SOC SQLite database. They are not live endpoint telemetry unless collection is running.")


from dashboard.pages.alerts import render_alert_management


def alert_management():
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
    page_header("Threat Hunting", "Search normalized endpoint telemetry using structured indicators and event context.", "HUNTING  /  EVENT SEARCH")
    c1, c2, c3 = st.columns(3)
    host = c1.text_input("Hostname")
    user = c2.text_input("Username")
    ip = c3.text_input("Source IP")
    c4, c5, c6 = st.columns(3)
    event_id = c4.text_input("Windows / Sysmon event ID")
    event_type = c5.text_input("Event type")
    general = c6.text_input("Image, command line or provider contains")
    limit = st.slider("Maximum results", 50, 1000, 300, 50)
    if st.button("⌕ Search events", type="primary"):
        st.session_state["hunt_results"] = search_events(hostname=host, username=user, source_ip=ip,
            event_id=event_id, event_type=event_type, search=general, limit=limit)
    rows = st.session_state.get("hunt_results", [])
    st.markdown(f"<span class='status-pill'>{len(rows)} EVENT(S)</span>", unsafe_allow_html=True)
    show_table(rows, "Configure one or more filters and run a search to view matching events.")


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


PAGE_FUNCTIONS = {
    "Overview": overview, "Alert Management": alert_management,
    "Investigations": investigations, "Threat Hunting": threat_hunting,
    "Evidence & Integrity": evidence_page, "Detection Intelligence": detection_intelligence,
    "Reports": reports_page,
}
PAGE_FUNCTIONS[page]()
