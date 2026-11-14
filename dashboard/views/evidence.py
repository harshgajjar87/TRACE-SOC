
"""TRACE-SOC Day 22: Digital evidence and chain-of-custody dashboard."""

import json
import streamlit as st

def page_header(title, subtitle, section="DFIR / EVIDENCE VAULT"):
    st.markdown(
        f"""
        <div class="top-banner">
            <div class="eyebrow">{section}</div>
            <div class="banner-title">{title}</div>
            <div class="banner-sub">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def show_table(rows, empty_message="No records found."):
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info(empty_message)
from investigation.evidence import (
    get_story_evidence,
    verify_raw_event_integrity,
)
from investigation.chain_of_custody import (
    create_chain_of_custody_schema,
    get_evidence_inventory,
    get_custody_history,
    get_raw_event_blob,
    record_custody_event,
    build_evidence_manifest,
)


def render_evidence():
    create_chain_of_custody_schema()

    page_header(
        "Evidence & Integrity",
        "Manage digital evidence, verify stored XML, and maintain an auditable chain of custody.",
        "DFIR / EVIDENCE VAULT",
    )

    actor = st.text_input(
        "Analyst identity",
        placeholder="Enter your analyst name or ID",
        help="This is an analyst-entered identity, not independently authenticated.",
        key="evidence_actor",
    )

    inventory_tab, story_tab, verify_tab, audit_tab = st.tabs(
        [
            "Evidence Inventory",
            "Story Evidence",
            "Integrity & Export",
            "Chain of Custody",
        ],
        key="evidence_active_tab",
    )

    with inventory_tab:
        st.subheader("Stored Evidence Inventory")
        limit = st.selectbox(
            "Maximum records",
            [100, 250, 500, 1000],
            index=2,
        )

        if st.button("Refresh inventory", key="refresh_evidence"):
            st.rerun()

        try:
            inventory = get_evidence_inventory(limit)
            if inventory:
                show_table(inventory)
                st.caption(f"Displaying {len(inventory)} evidence records.")
            else:
                st.info("No raw evidence records are currently stored.")
        except Exception as exc:
            st.error(f"Could not load evidence inventory: {exc}")

    with story_tab:
        st.subheader("Investigation-linked Evidence")
        story_id = st.number_input(
            "Investigation story ID",
            min_value=1,
            step=1,
            key="evidence_story_id",
        )

        if st.button("Load linked evidence", type="primary"):
            try:
                records = get_story_evidence(int(story_id))
                st.session_state["day22_story_evidence"] = records
                st.session_state["day22_story_id"] = int(story_id)
            except Exception as exc:
                st.error(f"Could not load story evidence: {exc}")

        records = st.session_state.get("day22_story_evidence", [])
        if records:
            show_table(records)
            st.caption(
                "These raw event records are linked to the selected "
                "investigation through story_events."
            )
        elif "day22_story_evidence" in st.session_state:
            st.info("No linked evidence was found for this story.")

    with verify_tab:
        st.subheader("Verify Evidence Integrity")

        evidence_id = st.number_input(
            "Raw event evidence ID",
            min_value=1,
            step=1,
            key="verify_evidence_id",
        )

        verify_reason = st.text_input(
            "Verification reason",
            value="Routine forensic integrity check",
            key="verify_reason",
        )

        if st.button("Verify SHA-256", type="primary"):
            try:
                result = verify_raw_event_integrity(int(evidence_id))
                st.session_state["day22_last_verification"] = result

                if actor.strip():
                    record_custody_event(
                        evidence_id,
                        "VERIFIED",
                        actor,
                        verify_reason,
                        sha256=result["actual_raw_xml_sha256"],
                        details={
                            "status": result["status"],
                            "expected_sha256": result["expected_raw_xml_sha256"],
                            "actual_sha256": result["actual_raw_xml_sha256"],
                        },
                    )
                else:
                    st.warning(
                        "Verification completed, but the audit record was "
                        "not saved because analyst identity is missing."
                    )

            except Exception as exc:
                st.error(f"Integrity verification failed: {exc}")

        result = st.session_state.get("day22_last_verification")
        if result:
            status = result["status"]

            if status == "VERIFIED":
                st.success("SHA-256 verification successful.")
            elif status == "MISMATCH":
                st.error("INTEGRITY MISMATCH: stored XML differs from baseline.")
            else:
                st.warning("No baseline hash is available for this evidence.")

            show_table([result])

        st.divider()
        st.subheader("Export Original XML and Manifest")

        export_id = st.number_input(
            "Evidence ID to export",
            min_value=1,
            step=1,
            key="export_evidence_id",
        )
        export_reason = st.text_input(
            "Export purpose",
            placeholder="Example: Academic forensic case review",
            key="export_reason",
        )

        if st.button("Prepare evidence export"):
            if not actor.strip():
                st.error("Enter your analyst identity before exporting.")
            elif not export_reason.strip():
                st.error("Enter the purpose of this export.")
            else:
                try:
                    verification = verify_raw_event_integrity(int(export_id))

                    if verification["status"] != "VERIFIED":
                        st.error(
                            "Export blocked: evidence does not have a "
                            "verified baseline. Resolve the integrity issue "
                            "before exporting."
                        )
                    else:
                        blob = get_raw_event_blob(int(export_id))

                        record_custody_event(
                            export_id,
                            "EXPORTED",
                            actor,
                            export_reason,
                            sha256=verification["actual_raw_xml_sha256"],
                            details={
                                "format": "XML",
                                "integrity_status": verification["status"],
                            },
                        )

                        manifest = build_evidence_manifest(
                            export_id,
                            verification,
                            actor,
                            export_reason,
                        )

                        st.session_state["day22_export"] = {
                            "id": int(export_id),
                            "xml": blob,
                            "manifest": manifest,
                        }
                        st.success("Evidence export prepared and audit record saved.")

                except Exception as exc:
                    st.error(f"Export preparation failed: {exc}")

        export = st.session_state.get("day22_export")
        if export:
            st.download_button(
                "Download original XML",
                data=export["xml"],
                file_name=f"TRACE-SOC-evidence-{export['id']}.xml",
                mime="application/xml",
                key="download_evidence_xml",
            )

            manifest_bytes = json.dumps(
                export["manifest"],
                indent=4,
                default=str,
            ).encode("utf-8")

            st.download_button(
                "Download evidence manifest",
                data=manifest_bytes,
                file_name=f"TRACE-SOC-evidence-{export['id']}-manifest.json",
                mime="application/json",
                key="download_evidence_manifest",
            )

            st.caption(
                "The export contains the stored XML bytes and a separate "
                "JSON manifest. Downloading does not modify the database evidence."
            )

    with audit_tab:
        st.subheader("Chain-of-Custody History")

        history_id = st.number_input(
            "Raw event evidence ID",
            min_value=1,
            step=1,
            key="history_evidence_id",
        )

        if st.button("Load custody history"):
            try:
                st.session_state["day22_custody_history"] = (
                    get_custody_history(int(history_id))
                )
            except Exception as exc:
                st.error(f"Could not load custody history: {exc}")

        history = st.session_state.get("day22_custody_history", [])
        if history:
            show_table(history)
        elif "day22_custody_history" in st.session_state:
            st.info("No custody history is recorded for this evidence.")

        st.divider()
        st.subheader("Record Evidence Access")

        access_id = st.number_input(
            "Evidence ID accessed",
            min_value=1,
            step=1,
            key="access_evidence_id",
        )
        access_reason = st.text_input(
            "Reason for access",
            placeholder="Example: Reviewing evidence for investigation",
            key="access_reason",
        )

        if st.button("Record evidence access"):
            if not actor.strip():
                st.error("Enter your analyst identity.")
            elif not access_reason.strip():
                st.error("Enter the reason for access.")
            else:
                try:
                    result = verify_raw_event_integrity(int(access_id))
                    record_custody_event(
                        access_id,
                        "ACCESSED",
                        actor,
                        access_reason,
                        sha256=result["actual_raw_xml_sha256"],
                        details={"integrity_status": result["status"]},
                    )
                    st.success("Evidence access recorded.")
                    st.session_state.pop("day22_custody_history", None)
                except Exception as exc:
                    st.error(f"Could not record access: {exc}")

        st.divider()
        st.subheader("Add Analyst Note")

        note_id = st.number_input(
            "Evidence ID for note",
            min_value=1,
            step=1,
            key="note_evidence_id",
        )
        note_text = st.text_area(
            "Custody note",
            placeholder="Describe the handling, review or observation.",
            key="custody_note_text",
        )

        if st.button("Record custody note"):
            if not actor.strip():
                st.error("Enter your analyst identity.")
            elif not note_text.strip():
                st.error("Enter a note.")
            else:
                try:
                    record_custody_event(
                        note_id,
                        "NOTE_ADDED",
                        actor,
                        note_text,
                        details={"note_type": "analyst_observation"},
                    )
                    st.success("Custody note recorded.")
                    st.session_state.pop("day22_custody_history", None)
                except Exception as exc:
                    st.error(f"Could not save custody note: {exc}")

    st.divider()
    st.caption(
        "Forensic limitation: SHA-256 verifies consistency with the stored "
        "baseline. The analyst identity is self-reported. This local audit "
        "trail is not a tamper-proof or independently authenticated evidence system."
    )


# Compatibility with the existing app navigation.
def render_evidence_page():
    render_evidence()
