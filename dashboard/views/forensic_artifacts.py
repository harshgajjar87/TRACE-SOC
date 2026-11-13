"""Day 23 dashboard view — Forensic Artifact Management."""

from __future__ import annotations

import streamlit as st

from forensics.engine import (
    ARTIFACT_TYPES, ARTIFACT_STATUSES,
    add_artifact, get_artifact, list_artifacts,
    update_artifact_status, add_artifact_note,
    get_artifact_summary,
)


def render_forensic_artifacts():
    st.markdown("""
    <div class='top-banner'>
      <div class='eyebrow'>FORENSICS  /  ARTIFACT MANAGEMENT</div>
      <div class='banner-title'>Forensic Artifacts</div>
      <div class='banner-sub'>Register, track and annotate forensic evidence artifacts collected during investigations.</div>
    </div>""", unsafe_allow_html=True)

    left, right = st.columns([3, 1])
    with right:
        if st.button("↻ Refresh", use_container_width=True):
            st.rerun()

    # Summary metrics
    summary = get_artifact_summary()
    cols = st.columns(4)
    metric_data = [
        ("TOTAL ARTIFACTS", summary.get("total", 0), "#67d5f5"),
        ("TYPES IN USE", len(summary.get("by_type", [])), "#a5b4fc"),
        ("HOSTS COVERED", len(summary.get("by_hostname", [])), "#34d399"),
        ("STATUSES", len(summary.get("by_status", [])), "#fbbf24"),
    ]
    for col, (label, value, color) in zip(cols, metric_data):
        with col:
            st.markdown(
                f"<div class='metric-card'>"
                f"<div class='metric-label'>{label}</div>"
                f"<div class='metric-value' style='color:{color};'>{value}</div>"
                f"</div>", unsafe_allow_html=True,
            )

    st.write("")
    tab1, tab2, tab3 = st.tabs(["📋 Artifact Registry", "➕ Register Artifact", "📝 Manage Artifact"])

    with tab1:
        f1, f2, f3 = st.columns([1, 1, 1])
        ftype = f1.selectbox("Type", ["ALL", *ARTIFACT_TYPES], key="fa_type")
        fstatus = f2.selectbox("Status", ["ALL", *ARTIFACT_STATUSES], key="fa_status")
        fhost = f3.text_input("Hostname filter", key="fa_host")

        artifacts = list_artifacts(
            artifact_type=ftype if ftype != "ALL" else None,
            status=fstatus if fstatus != "ALL" else None,
            hostname=fhost or None,
            limit=300,
        )

        if artifacts:
            display = [{
                "id": a["id"],
                "type": a["artifact_type"],
                "name": a["name"],
                "hostname": a["hostname"] or "—",
                "analyst": a["analyst"],
                "status": a["status"],
                "sha256": (str(a.get("sha256") or "")[:16] + "…") if a.get("sha256") else "—",
                "collected": str(a.get("collected_at_utc") or "")[:19].replace("T", " "),
            } for a in artifacts]
            st.dataframe(display, use_container_width=True, hide_index=True)
        else:
            st.info("No artifacts found with the current filters.")

    with tab2:
        with st.form("register_artifact"):
            st.markdown("<div class='section-kicker'>REGISTER NEW ARTIFACT</div>", unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            art_type = c1.selectbox("Artifact type", ARTIFACT_TYPES)
            art_status = c2.selectbox("Initial status", ARTIFACT_STATUSES)
            art_name = st.text_input("Artifact name *")
            art_host = st.text_input("Hostname")
            art_analyst = st.text_input("Analyst *")
            art_sha256 = st.text_input("SHA-256 hash (optional)")
            art_path = st.text_input("File path (optional)")
            art_desc = st.text_area("Description")
            art_story = st.number_input("Link to story ID (0 = none)", min_value=0, step=1, value=0)
            art_tags = st.text_input("Tags (comma-separated)")

            if st.form_submit_button("Register Artifact", type="primary"):
                if not art_name.strip() or not art_analyst.strip():
                    st.error("Artifact name and analyst are required.")
                else:
                    tags = [t.strip() for t in art_tags.split(",") if t.strip()]
                    try:
                        new_id = add_artifact(
                            artifact_type=art_type,
                            name=art_name.strip(),
                            analyst=art_analyst.strip(),
                            hostname=art_host.strip(),
                            description=art_desc.strip(),
                            sha256=art_sha256.strip() or None,
                            file_path=art_path.strip() or None,
                            status=art_status,
                            story_id=int(art_story) if art_story else None,
                            tags=tags,
                        )
                        st.success(f"Artifact #{new_id} registered successfully.")
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))

    with tab3:
        artifact_id = st.number_input("Artifact ID", min_value=1, step=1, key="manage_art_id")
        if st.button("Load artifact", key="load_art"):
            art = get_artifact(int(artifact_id))
            if art:
                st.json({k: v for k, v in art.items() if k != "notes"})
                notes = art.get("notes", [])
                if notes:
                    st.markdown("<div class='section-kicker'>NOTES</div>", unsafe_allow_html=True)
                    for n in notes:
                        st.markdown(
                            f"**{n['analyst']}** — {str(n['recorded_at_utc'])[:19].replace('T', ' ')}  \n{n['note']}"
                        )
            else:
                st.warning(f"Artifact #{artifact_id} not found.")

        st.write("")
        st.markdown("<div class='section-kicker'>UPDATE STATUS</div>", unsafe_allow_html=True)
        with st.form("update_status_form"):
            new_status = st.selectbox("New status", ARTIFACT_STATUSES)
            upd_analyst = st.text_input("Analyst")
            if st.form_submit_button("Update Status"):
                if not upd_analyst.strip():
                    st.error("Analyst identity is required.")
                else:
                    ok = update_artifact_status(int(artifact_id), new_status, upd_analyst.strip())
                    if ok:
                        st.success("Status updated.")
                    else:
                        st.warning("Artifact not found or no change made.")

        st.markdown("<div class='section-kicker'>ADD NOTE</div>", unsafe_allow_html=True)
        with st.form("add_note_form"):
            note_analyst = st.text_input("Analyst", key="note_analyst")
            note_text = st.text_area("Note")
            if st.form_submit_button("Add Note"):
                if not note_analyst.strip() or not note_text.strip():
                    st.error("Analyst and note text are required.")
                else:
                    try:
                        note_id = add_artifact_note(int(artifact_id), note_analyst.strip(), note_text.strip())
                        st.success(f"Note #{note_id} added.")
                    except ValueError as exc:
                        st.error(str(exc))
