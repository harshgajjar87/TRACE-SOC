"""TRACE-SOC analyst dashboard. Run: streamlit run dashboard/app.py"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure project root is importable when Streamlit launches this file directly.
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
from dashboard.data_access import (ALERT_STATUSES, SEVERITIES, ensure_dashboard_schema,
    get_dashboard_summary, get_alerts, update_alert_status, get_alert_status_history,
    get_stories, search_events)
from investigation.investigation_queries import get_investigation
from investigation.evidence import get_story_evidence, verify_raw_event_integrity
from reports.pdf_generator import generate_investigation_pdf

st.set_page_config(page_title="TRACE-SOC | Analyst Workspace", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 1.5rem; padding-bottom: 2rem;}
[data-testid="stMetric"] {background: rgba(100,116,139,.08); padding: 14px; border-radius: 10px;}
div[data-testid="stDataFrame"] {border: 1px solid rgba(128,128,128,.18); border-radius: 8px;}
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

st.sidebar.title("🛡️ TRACE-SOC")
st.sidebar.caption("Security Operations & Digital Forensics")
page = st.sidebar.radio("WORKSPACE", ["Overview", "Alert Management", "Investigations", "Threat Hunting", "Evidence & Integrity", "Detection Intelligence", "Reports"])
st.sidebar.divider()
st.sidebar.caption("Local SQLite deployment")


def show_table(rows, empty_message="No records found."):
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info(empty_message)


def overview():
    st.title("Security Overview")
    st.caption("A unified view of collected telemetry, detections and investigations.")
    data=get_dashboard_summary(); c=data["counts"]
    cols=st.columns(5)
    for col,label,key in zip(cols,["Normalized events","Detection alerts","Open alerts","Critical open","Attack stories"],
        ["total_events","total_alerts","open_alerts","critical_alerts","total_stories"]):
        col.metric(label, f"{c.get(key,0):,}")
    left,right=st.columns(2)
    with left:
        st.subheader("Alerts by severity")
        if data["severity"]:
            st.plotly_chart(px.bar(data["severity"],x="severity",y="count",color="severity",title="Severity distribution"),use_container_width=True)
        else: st.info("No alerts have been generated yet.")
    with right:
        st.subheader("Alert workflow")
        if data["status"]:
            st.plotly_chart(px.pie(data["status"],names="status",values="count",hole=.48,title="Alert status distribution"),use_container_width=True)
        else: st.info("No alert workflow records yet.")
    st.subheader("Event categories")
    if data["event_categories"]:
        st.plotly_chart(px.bar(data["event_categories"],x="count",y="category",orientation="h",title="Top normalized event categories"),use_container_width=True)
    st.subheader("Recent alerts")
    show_table(data["recent_alerts"])
    st.caption("Dashboard metrics are calculated from the local TRACE-SOC SQLite database; they are not live endpoint telemetry unless collection is running.")


def alert_management():
    st.title("Alert Management")
    st.caption("Triage alerts and retain an audit history of analyst status changes.")
    f1,f2,f3=st.columns([1,1,2])
    status=f1.selectbox("Status",["ALL",*ALERT_STATUSES])
    severity=f2.selectbox("Severity",["ALL",*SEVERITIES])
    search=f3.text_input("Search rule, host, user or IP")
    alerts=get_alerts(status=status,severity=severity,search=search)
    st.write(f"**{len(alerts)}** alert(s) returned (maximum 200 shown).")
    show_table([{k:a.get(k) for k in ["id","rule_id","rule_name","severity","status","hostname","username","source_ip","event_count","created_at_utc"]} for a in alerts])
    if not alerts: return
    st.divider(); st.subheader("Update alert")
    ids=[a["id"] for a in alerts]
    selected=st.selectbox("Select alert ID",ids,format_func=lambda x: f"#{x} — {next(a['rule_name'] for a in alerts if a['id']==x)}")
    chosen=next(a for a in alerts if a["id"]==selected)
    st.write(f"**{chosen['rule_id']} · {chosen['severity']}** — {chosen.get('description') or 'No description'}")
    current=chosen.get("status","NEW")
    new_status=st.selectbox("New status",ALERT_STATUSES,index=ALERT_STATUSES.index(current) if current in ALERT_STATUSES else 0)
    note=st.text_input("Analyst note (optional)",key=f"note_{selected}")
    if st.button("Save alert status",type="primary"):
        try:
            if update_alert_status(selected,new_status,note):
                st.success("Alert status saved and recorded in status history.")
                st.rerun()
            else: st.error("Alert not found.")
        except ValueError as exc: st.error(str(exc))
    history=get_alert_status_history(selected)
    with st.expander("Status change history"):
        show_table(history,"No status changes recorded for this alert.")


def investigations():
    st.title("Attack Investigations")
    f1,f2,f3=st.columns([1,1,2])
    status=f1.selectbox("Story status",["ALL",*ALERT_STATUSES],key="story_status")
    severity=f2.selectbox("Story severity",["ALL",*SEVERITIES],key="story_severity")
    search=f3.text_input("Search title, host, username or source IP",key="story_search")
    stories=get_stories(status=status,severity=severity,search=search)
    show_table([{k:s.get(k) for k in ["id","title","severity","status","hostname","username","source_ip","event_count","alert_count","confidence_score","confidence_level","first_seen","last_seen"]} for s in stories])
    if stories:
        selected=st.selectbox("Open investigation",[s["id"] for s in stories],format_func=lambda x:f"#{x} — {next(s['title'] for s in stories if s['id']==x)}")
        result=get_investigation(selected); story=result["story"]
        st.subheader(f"Investigation #{selected}: {story['title']}")
        st.write(story.get("description") or "No description")
        st.write(f"**Confidence:** {story.get('confidence_score',0)} / {story.get('confidence_level','LOW')} — heuristic relationship strength, not attack probability.")
        st.markdown("**Chronological timeline**")
        show_table([{k:e.get(k) for k in ["timestamp_utc","normalized_event_id","event_id","event_type","hostname","username","source_ip","destination_ip","image","command_line","rule_id","rule_name","alert_severity","raw_event_id"]} for e in result.get("timeline",[])])
        with st.expander("Correlation relationships"):
            show_table(result.get("relationships",[]),"No relationship edges stored.")
        with st.expander("Linked alerts"):
            show_table([{k:a.get(k) for k in ["id","rule_id","rule_name","severity","status","created_at_utc"]} for a in result.get("alerts",[])])


def threat_hunting():
    st.title("Threat Hunting")
    st.caption("Search normalized endpoint events using structured filters.")
    c1,c2,c3=st.columns(3)
    host=c1.text_input("Hostname")
    user=c2.text_input("Username")
    ip=c3.text_input("Source IP")
    c4,c5,c6=st.columns(3)
    event_id=c4.text_input("Windows / Sysmon event ID")
    event_type=c5.text_input("Event type")
    general=c6.text_input("Image, command line or provider contains")
    limit=st.slider("Maximum results",50,1000,300,50)
    if st.button("Search events",type="primary"):
        rows=search_events(hostname=host,username=user,source_ip=ip,event_id=event_id,event_type=event_type,search=general,limit=limit)
        st.session_state["hunt_results"]=rows
    rows=st.session_state.get("hunt_results",[])
    st.write(f"**{len(rows)}** event(s)")
    show_table(rows,"Run a search to view matching events.")


def evidence_page():
    st.title("Evidence & Integrity")
    story_id=st.number_input("Investigation story ID",min_value=1,step=1)
    if st.button("Load linked evidence"):
        try:
            records=get_story_evidence(int(story_id)); st.session_state["evidence_records"]=records
        except Exception as exc: st.error(str(exc))
    records=st.session_state.get("evidence_records",[])
    if records:
        from investigation.evidence import verify_raw_event_integrity
        checks=[]
        for item in records:
            check=verify_raw_event_integrity(item["raw_event_id"])
            checks.append({"raw_event_id":item["raw_event_id"],"source_file":item.get("source_file"),"raw_xml_sha256":item.get("raw_xml_sha256"),"status":check["status"]})
        show_table(checks)
        st.caption("VERIFIED means the stored XML blob matches its recorded hash baseline; it does not independently prove original evidence authenticity.")
    elif "evidence_records" in st.session_state: st.info("No linked evidence records found for this story.")


def detection_intelligence():
    st.title("Detection Intelligence")
    from detection.rules import DETECTION_RULES
    from detection.coverage import DETECTION_COVERAGE
    rules=DETECTION_RULES
    st.metric("Configured detection rules",len(rules))
    by_category={}
    for rule in rules:
        category=rule.get("category","uncategorized")
        by_category[category]=by_category.get(category,0)+1
    if by_category:
        st.plotly_chart(px.bar(x=list(by_category),y=list(by_category.values()),labels={"x":"Category","y":"Rules"},title="Configured rules by category"),use_container_width=True)
    show_table([{k:r.get(k) for k in ["rule_id","name","category","rule_type","severity","mitre_tactic","mitre_technique"]} for r in rules])
    st.info("Configured rules describe intended detection logic. This view does not claim every attack technique is covered or that every rule has fired in production.")
    with st.expander("Coverage registry"):
        st.json(DETECTION_COVERAGE)


def reports_page():
    st.title("Investigation Reports")
    stories=get_stories(limit=500)
    if not stories: st.info("No investigation stories are available to report."); return
    selected=st.selectbox("Select investigation",[s["id"] for s in stories],format_func=lambda x:f"#{x} — {next(s['title'] for s in stories if s['id']==x)}")
    st.write("The PDF includes the story summary, chronological event timeline, linked alerts and evidence hash verification references.")
    if st.button("Generate PDF report",type="primary"):
        try:
            pdf=generate_investigation_pdf(selected)
            st.download_button("Download investigation PDF",data=pdf,file_name=f"TRACE-SOC-investigation-{selected}.pdf",mime="application/pdf")
        except Exception as exc: st.error(f"Report generation failed: {exc}")


PAGES={"Overview":overview,"Alert Management":alert_management,"Investigations":investigations,
       "Threat Hunting":threat_hunting,"Evidence & Integrity":evidence_page,
       "Detection Intelligence":detection_intelligence,"Reports":reports_page}
PAGES[page]()
