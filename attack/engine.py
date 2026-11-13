
"""TRACE-SOC MITRE ATT&CK mapping and coverage engine."""

import re

from datetime import datetime, timezone

from database.db import get_connection


TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def validate_technique_id(technique_id):
    """Validate MITRE ATT&CK technique or sub-technique ID."""

    technique_id = str(technique_id or "").strip().upper()

    if not TECHNIQUE_PATTERN.fullmatch(technique_id):
        raise ValueError(
            "Invalid technique ID. Expected format such as T1110 or T1059.001."
        )

    return technique_id


def create_attack_schema():
    """Create MITRE ATT&CK catalog and alert mapping tables."""

    conn = get_connection()

    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS attack_technique_catalog (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT NOT NULL UNIQUE,
                technique_name TEXT NOT NULL,
                tactic TEXT NOT NULL,
                description TEXT,
                source TEXT NOT NULL DEFAULT 'ANALYST_VERIFIED',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attack_alert_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                technique_id TEXT NOT NULL,
                tactic TEXT NOT NULL,
                mapping_source TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT 'UNSPECIFIED',
                mapped_at_utc TEXT NOT NULL,
                UNIQUE(alert_id, technique_id, tactic),
                FOREIGN KEY(alert_id)
                    REFERENCES alerts(id),
                FOREIGN KEY(technique_id)
                    REFERENCES attack_technique_catalog(technique_id)
            );

            CREATE INDEX IF NOT EXISTS idx_attack_mapping_alert
            ON attack_alert_mappings(alert_id);

            CREATE INDEX IF NOT EXISTS idx_attack_mapping_technique
            ON attack_alert_mappings(technique_id);

            CREATE INDEX IF NOT EXISTS idx_attack_mapping_tactic
            ON attack_alert_mappings(tactic);
        """)

        conn.commit()

    finally:
        conn.close()


def register_technique(
    technique_id,
    technique_name,
    tactic,
    description="",
):
    """
    Register or update verified ATT&CK technique metadata.

    The caller is responsible for verifying the technique and tactic
    against an authoritative MITRE ATT&CK reference.
    """

    technique_id = validate_technique_id(technique_id)
    technique_name = str(technique_name or "").strip()
    tactic = str(tactic or "").strip()
    description = str(description or "").strip()

    if not technique_name:
        raise ValueError("Technique name is required.")

    if not tactic:
        raise ValueError("ATT&CK tactic is required.")

    if len(technique_name) > 200:
        raise ValueError("Technique name is too long.")

    if len(tactic) > 100:
        raise ValueError("Tactic name is too long.")

    conn = get_connection()

    try:
        now = utc_now()

        conn.execute("""
            INSERT INTO attack_technique_catalog (
                technique_id,
                technique_name,
                tactic,
                description,
                source,
                created_at_utc,
                updated_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(technique_id)
            DO UPDATE SET
                technique_name = excluded.technique_name,
                tactic = excluded.tactic,
                description = excluded.description,
                source = excluded.source,
                updated_at_utc = excluded.updated_at_utc
        """, (
            technique_id,
            technique_name,
            tactic,
            description,
            "ANALYST_VERIFIED",
            now,
            now,
        ))

        conn.commit()

    finally:
        conn.close()

    return technique_id


def get_techniques():
    """Return the configured technique catalog."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT *
            FROM attack_technique_catalog
            ORDER BY tactic, technique_id
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_alert_mitre_fields():
    """Retrieve existing MITRE mappings from security alerts."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                id,
                rule_id,
                rule_name,
                mitre_tactic,
                mitre_technique
            FROM alerts
            ORDER BY id
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def sync_alert_mappings():
    """
    Synchronize mappings already present in alerts.

    This function does not invent technique names or mappings.
    Existing alert technique IDs are added to the catalog with
    placeholder metadata until verified by an analyst.
    """

    alerts = get_alert_mitre_fields()

    conn = get_connection()

    try:
        mapped_count = 0
        skipped_count = 0

        for alert in alerts:

            raw_technique = alert.get("mitre_technique")
            raw_tactic = alert.get("mitre_tactic")

            if not raw_technique or not raw_tactic:
                skipped_count += 1
                continue

            try:
                technique_id = validate_technique_id(raw_technique)
            except ValueError:
                skipped_count += 1
                continue

            tactic = str(raw_tactic).strip()

            if not tactic:
                skipped_count += 1
                continue

            now = utc_now()

            existing = conn.execute("""
                SELECT technique_id
                FROM attack_technique_catalog
                WHERE technique_id = ?
            """, (technique_id,)).fetchone()

            if not existing:

                conn.execute("""
                    INSERT INTO attack_technique_catalog (
                        technique_id,
                        technique_name,
                        tactic,
                        description,
                        source,
                        created_at_utc,
                        updated_at_utc
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    technique_id,
                    "Name requires verification",
                    tactic,
                    "Technique metadata imported from an existing alert.",
                    "ALERT_METADATA_UNVERIFIED",
                    now,
                    now,
                ))

            conn.execute("""
                INSERT OR IGNORE INTO attack_alert_mappings (
                    alert_id,
                    technique_id,
                    tactic,
                    mapping_source,
                    confidence,
                    mapped_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                alert["id"],
                technique_id,
                tactic,
                "EXISTING_ALERT_METADATA",
                "UNVERIFIED",
                now,
            ))

            mapped_count += 1

        conn.commit()

        return {
            "processed_alerts": len(alerts),
            "mapped_records": mapped_count,
            "skipped_alerts": skipped_count,
        }

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def map_alert_to_technique(
    alert_id,
    technique_id,
    tactic,
    mapped_by,
    confidence="MEDIUM",
):
    """Manually map an alert to an existing verified technique."""

    technique_id = validate_technique_id(technique_id)
    tactic = str(tactic or "").strip()
    mapped_by = str(mapped_by or "").strip()
    confidence = str(confidence or "").upper().strip()

    if not tactic:
        raise ValueError("Tactic is required.")

    if not mapped_by:
        raise ValueError("Analyst name is required.")

    if len(mapped_by) > 120:
        raise ValueError("Analyst name must be 120 characters or fewer.")

    if confidence not in ("LOW", "MEDIUM", "HIGH"):
        raise ValueError("Confidence must be LOW, MEDIUM or HIGH.")

    conn = get_connection()

    try:
        alert = conn.execute("""
            SELECT id
            FROM alerts
            WHERE id = ?
        """, (alert_id,)).fetchone()

        if not alert:
            raise ValueError("Alert does not exist.")

        technique = conn.execute("""
            SELECT technique_id, tactic
            FROM attack_technique_catalog
            WHERE technique_id = ?
        """, (technique_id,)).fetchone()

        if not technique:
            raise ValueError(
                "Technique is not registered. Register verified metadata first."
            )

        if technique["tactic"].casefold() != tactic.casefold():
            raise ValueError(
                "Selected tactic does not match the registered technique metadata."
            )

        conn.execute("""
            INSERT OR IGNORE INTO attack_alert_mappings (
                alert_id,
                technique_id,
                tactic,
                mapping_source,
                confidence,
                mapped_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            technique_id,
            technique["tactic"],
            f"ANALYST:{mapped_by}",
            confidence,
            utc_now(),
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_mapped_alerts():
    """Return alerts with their ATT&CK mappings."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                a.id AS alert_id,
                a.rule_id,
                a.rule_name,
                a.severity,
                a.status,
                a.hostname,
                m.technique_id,
                t.technique_name,
                m.tactic,
                m.mapping_source,
                m.confidence,
                m.mapped_at_utc
            FROM attack_alert_mappings m
            JOIN alerts a
                ON a.id = m.alert_id
            JOIN attack_technique_catalog t
                ON t.technique_id = m.technique_id
            ORDER BY a.id DESC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_unmapped_alerts():
    """Return alerts without any ATT&CK mapping."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                a.id,
                a.rule_id,
                a.rule_name,
                a.severity,
                a.status,
                a.mitre_tactic,
                a.mitre_technique
            FROM alerts a
            LEFT JOIN attack_alert_mappings m
                ON m.alert_id = a.id
            WHERE m.id IS NULL
            ORDER BY a.id DESC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_technique_coverage():
    """Return technique catalog coverage and mapped alert counts."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                t.technique_id,
                t.technique_name,
                t.tactic,
                t.source,
                COUNT(DISTINCT m.alert_id) AS mapped_alert_count
            FROM attack_technique_catalog t
            LEFT JOIN attack_alert_mappings m
                ON m.technique_id = t.technique_id
            GROUP BY
                t.technique_id,
                t.technique_name,
                t.tactic,
                t.source
            ORDER BY t.tactic, t.technique_id
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_tactic_distribution():
    """Return number of mapped alerts per tactic."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                tactic,
                COUNT(DISTINCT alert_id) AS alert_count,
                COUNT(DISTINCT technique_id) AS technique_count
            FROM attack_alert_mappings
            GROUP BY tactic
            ORDER BY alert_count DESC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_attack_coverage_summary():
    """
    Return alert mapping and configured technique coverage statistics.

    Catalog coverage is based only on techniques registered in this
    project's catalog. It is not the percentage of all MITRE ATT&CK.
    """

    conn = get_connection()

    try:
        total_alerts = conn.execute("""
            SELECT COUNT(*) FROM alerts
        """).fetchone()[0]

        mapped_alerts = conn.execute("""
            SELECT COUNT(DISTINCT alert_id)
            FROM attack_alert_mappings
        """).fetchone()[0]

        total_techniques = conn.execute("""
            SELECT COUNT(*)
            FROM attack_technique_catalog
        """).fetchone()[0]

        observed_techniques = conn.execute("""
            SELECT COUNT(DISTINCT technique_id)
            FROM attack_alert_mappings
        """).fetchone()[0]

        verified_techniques = conn.execute("""
            SELECT COUNT(*)
            FROM attack_technique_catalog
            WHERE source = 'ANALYST_VERIFIED'
        """).fetchone()[0]

        unmapped_alerts = total_alerts - mapped_alerts

        return {
            "total_alerts": total_alerts,
            "mapped_alerts": mapped_alerts,
            "unmapped_alerts": unmapped_alerts,
            "alert_mapping_percentage": (
                round(mapped_alerts / total_alerts * 100, 2)
                if total_alerts else 0
            ),
            "total_catalog_techniques": total_techniques,
            "observed_techniques": observed_techniques,
            "verified_techniques": verified_techniques,
            "catalog_observation_percentage": (
                round(
                    observed_techniques / total_techniques * 100,
                    2,
                )
                if total_techniques else 0
            ),
        }

    finally:
        conn.close()


def get_technique_details(technique_id):
    """Return technique metadata and associated alerts."""

    technique_id = validate_technique_id(technique_id)

    conn = get_connection()

    try:
        technique = conn.execute("""
            SELECT *
            FROM attack_technique_catalog
            WHERE technique_id = ?
        """, (technique_id,)).fetchone()

        if not technique:
            return None

        alerts = conn.execute("""
            SELECT
                a.id,
                a.rule_id,
                a.rule_name,
                a.severity,
                a.status,
                m.mapping_source,
                m.confidence
            FROM attack_alert_mappings m
            JOIN alerts a
                ON a.id = m.alert_id
            WHERE m.technique_id = ?
            ORDER BY a.id DESC
        """, (technique_id,)).fetchall()

        return {
            "technique": dict(technique),
            "alerts": [dict(row) for row in alerts],
        }

    finally:
        conn.close()
