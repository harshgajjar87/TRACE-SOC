"""Day 27 dashboard view — Analyst Report Center."""

from __future__ import annotations

import streamlit as st

from dashboard.data_access import get_stories
from reports.analyst_report import (
    get_story_brief,
    get_multi_story_briefs,
    build_executive_summary_text,
    generate_executive_summary_pdf,
    generate_single_story_text_report,
)


def render_analyst_reports():
    st.markdown("""
    <div class='top-banner'>
      <div class='eyebrow'>REPORTS  /  ANALYST CENTER</div>
      <div class='banner-title'>Analyst Report Center</div>
      <div class='banner-sub'>Generate investigation briefs, multi-story executive summaries and exportable reports.</div>
    </div>""", unsafe_allow_html=True)

    left, right = st.columns([3, 1])
    with right:
        if st.button("↻ Refresh", use_container_width=True):
            st.rerun()

    stories = get_stories(status="ALL", limit=1000)

    if not stories:
        st.info("No investigation stories are available. Run the detection and correlation engines to generate stories.")
        return

    tab1, tab2, tab3 = st.tabs(
        ["📄 Single Investigation", "📊 Executive Summary", "📋 Batch Export"],
        key="analyst_reports_active_tab",
    )

    with tab1:
        st.markdown("<div class='section-kicker'>SINGLE INVESTIGATION REPORT</div>", unsafe_allow_html=True)
        selected_id = st.selectbox(
            "Select investigation",
            [s["id"] for s in stories],
            format_func=lambda x: f"#{x} — {next(s['title'] for s in stories if s['id'] == x)}",
            key="ar_single_id",
        )

        if st.button("Generate Report", type="primary", key="ar_gen_single"):
            try:
                brief = get_story_brief(selected_id)
            except ValueError as exc:
                st.error(str(exc))
                return

            # Display the brief inline
            st.markdown(f"### Case #{brief['story_id']} — {brief['title']}")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Severity", brief["severity"])
            m2.metric("Status", brief["status"])
            m3.metric("Events", brief["event_count"])
            m4.metric("Alerts", brief["alert_count"])

            if brief.get("description"):
                st.write(brief["description"])

            st.caption(
                f"Period: {brief['first_seen']} → {brief['last_seen']}  |  "
                f"Confidence: {brief['confidence_score']} ({brief['confidence_level']})"
            )

            if brief.get("mitre_tactics"):
                st.markdown("**MITRE Tactics:** " + ", ".join(brief["mitre_tactics"]))
            if brief.get("affected_hosts"):
                st.markdown("**Hosts:** " + ", ".join(brief["affected_hosts"]))
            if brief.get("affected_users"):
                st.markdown("**Users:** " + ", ".join(brief["affected_users"]))
            if brief.get("source_ips"):
                st.markdown("**Source IPs:** " + ", ".join(brief["source_ips"]))

            # Timeline excerpt
            if brief.get("timeline_summary"):
                st.markdown("<div class='section-kicker'>TIMELINE EXCERPT</div>", unsafe_allow_html=True)
                tl_display = [{
                    "timestamp": str(e.get("timestamp_utc") or "")[:19].replace("T", " "),
                    "event_id": e.get("event_id"),
                    "hostname": e.get("hostname"),
                    "username": e.get("username"),
                    "image": str(e.get("image") or "")[-60:],
                } for e in brief["timeline_summary"]]
                st.dataframe(tl_display, use_container_width=True, hide_index=True)

            # Download buttons
            col1, col2 = st.columns(2)
            with col1:
                txt_bytes = generate_single_story_text_report(selected_id)
                st.download_button(
                    "⬇ Download Text Report",
                    data=txt_bytes,
                    file_name=f"TRACE-SOC-report-{selected_id}.txt",
                    mime="text/plain",
                )
            with col2:
                try:
                    pdf_bytes = generate_executive_summary_pdf([brief])
                    st.download_button(
                        "⬇ Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"TRACE-SOC-report-{selected_id}.pdf",
                        mime="application/pdf",
                    )
                except Exception as exc:
                    st.warning(f"PDF generation failed: {exc}")

    with tab2:
        st.markdown("<div class='section-kicker'>EXECUTIVE SUMMARY — MULTIPLE INVESTIGATIONS</div>", unsafe_allow_html=True)

        status_options = ["ALL", "NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
        exec_status = st.selectbox("Include investigations with status", status_options, key="ar_exec_status")

        if exec_status == "ALL":
            candidate_ids = [s["id"] for s in stories]
        else:
            candidate_ids = [s["id"] for s in stories if str(s.get("status", "")).upper() == exec_status]

        st.caption(f"{len(candidate_ids)} investigations will be included.")

        if st.button("Generate Executive Summary", type="primary", key="ar_exec_gen"):
            with st.spinner("Building executive summary…"):
                briefs = get_multi_story_briefs(candidate_ids)

            if not briefs:
                st.warning("No stories could be loaded.")
            else:
                # Preview
                with st.expander("Preview (plain text)", expanded=False):
                    st.text(build_executive_summary_text(briefs))

                # Download
                col1, col2 = st.columns(2)
                with col1:
                    txt_data = build_executive_summary_text(briefs).encode("utf-8")
                    st.download_button(
                        "⬇ Download Text Summary",
                        data=txt_data,
                        file_name="TRACE-SOC-executive-summary.txt",
                        mime="text/plain",
                        key="ar_dl_txt",
                    )
                with col2:
                    try:
                        pdf_data = generate_executive_summary_pdf(briefs)
                        st.download_button(
                            "⬇ Download PDF Summary",
                            data=pdf_data,
                            file_name="TRACE-SOC-executive-summary.pdf",
                            mime="application/pdf",
                            key="ar_dl_pdf",
                        )
                    except Exception as exc:
                        st.warning(f"PDF generation failed: {exc}")

    with tab3:
        st.markdown("<div class='section-kicker'>BATCH EXPORT — SELECT INVESTIGATIONS</div>", unsafe_allow_html=True)
        st.caption("Select specific investigations for a combined report.")

        story_options = {f"#{s['id']} — {s['title']}": s["id"] for s in stories}
        selected_labels = st.multiselect("Select investigations", list(story_options.keys()), key="ar_batch_sel")
        selected_batch_ids = [story_options[lbl] for lbl in selected_labels]

        if selected_batch_ids and st.button("Generate Batch Report", type="primary", key="ar_batch_gen"):
            with st.spinner("Building report…"):
                briefs = get_multi_story_briefs(selected_batch_ids)

            if not briefs:
                st.warning("None of the selected stories could be loaded.")
            else:
                st.success(f"Built report for {len(briefs)} investigation(s).")
                txt_data = build_executive_summary_text(briefs).encode("utf-8")
                st.download_button(
                    "⬇ Download Batch Report (Text)",
                    data=txt_data,
                    file_name="TRACE-SOC-batch-report.txt",
                    mime="text/plain",
                    key="ar_batch_dl",
                )
                try:
                    pdf_data = generate_executive_summary_pdf(briefs)
                    st.download_button(
                        "⬇ Download Batch Report (PDF)",
                        data=pdf_data,
                        file_name="TRACE-SOC-batch-report.pdf",
                        mime="application/pdf",
                        key="ar_batch_dl_pdf",
                    )
                except Exception as exc:
                    st.warning(f"PDF generation failed: {exc}")
        elif not selected_batch_ids:
            st.info("Select at least one investigation above.")
