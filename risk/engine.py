
"""TRACE-SOC advanced threat correlation and risk scoring engine."""

import json

from datetime import datetime, timedelta, timezone

from database.db import get_connection


SEVERITY_POINTS = {
    "CRITICAL": 35,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 8,
    "INFO": 3,
}

RISK_LEVELS = {
    "CRITICAL": (80, 100),
    "HIGH": (60, 79),
    "MEDIUM": (35, 59),
    "LOW": (0, 34),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def parse_timestamp(value):
    """Parse ISO timestamps safely into UTC."""

    if not value:
        return None

    try:
        result = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def classify_risk(score):
    """Convert numeric risk score into a risk category."""

    score = max(0, min(int(score), 100))

    for level, (minimum, maximum) in RISK_LEVELS.items():

        if minimum <= score <= maximum:
            return level

    return "LOW"


def create_risk_schema():
    """Create persistent risk assessment history."""

    conn = get_connection()

    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alert_risk_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                factors_json TEXT NOT NULL,
                related_alert_ids_json TEXT NOT NULL,
                assessed_at_utc TEXT NOT NULL,
                FOREIGN KEY(alert_id)
                    REFERENCES alerts(id)
            );

            CREATE INDEX IF NOT EXISTS idx_risk_alert
            ON alert_risk_assessments(alert_id);

            CREATE INDEX IF NOT EXISTS idx_risk_score
            ON alert_risk_assessments(risk_score);

            CREATE INDEX IF NOT EXISTS idx_risk_level
            ON alert_risk_assessments(risk_level);

            CREATE INDEX IF NOT EXISTS idx_risk_assessed
            ON alert_risk_assessments(assessed_at_utc);
        """)

        conn.commit()

    finally:
        conn.close()


def get_alert(alert_id):
    """Retrieve one alert."""

    conn = get_connection()

    try:
        row = conn.execute("""
            SELECT *
            FROM alerts
            WHERE id = ?
        """, (alert_id,)).fetchone()

        return dict(row) if row else None

    finally:
        conn.close()


def get_all_alerts():
    """Retrieve all alerts."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT *
            FROM alerts
            ORDER BY id DESC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_linked_events(alert_id):
    """Retrieve normalized events linked to an alert."""

    conn = get_connection()

    try:
        row = conn.execute("""
            SELECT evidence_json
            FROM alerts
            WHERE id = ?
        """, (alert_id,)).fetchone()

        if not row:
            return []

        try:
            evidence = json.loads(row["evidence_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            evidence = {}

        event_ids = evidence.get("normalized_event_ids", [])

        if not isinstance(event_ids, list):
            return []

        valid_ids = []

        for value in event_ids:
            try:
                event_id = int(value)

                if event_id > 0 and event_id not in valid_ids:
                    valid_ids.append(event_id)

            except (TypeError, ValueError):
                continue

        if not valid_ids:
            return []

        placeholders = ",".join("?" for _ in valid_ids)

        rows = conn.execute(f"""
            SELECT
                id,
                hostname,
                username,
                source_ip,
                destination_ip,
                event_id,
                timestamp_utc
            FROM normalized_events
            WHERE id IN ({placeholders})
        """, valid_ids).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_ioc_matches(alert_id):
    """
    Find exact IP matches in the local threat intelligence inventory.

    Matches source and destination IPs from normalized events.
    """

    events = get_linked_events(alert_id)

    ips = set()

    for event in events:

        for field in ("source_ip", "destination_ip"):

            value = event.get(field)

            if value:
                value = str(value).strip()

                if value and value != "-":
                    ips.add(value)

    if not ips:
        return []

    conn = get_connection()

    try:

        placeholders = ",".join("?" for _ in ips)

        rows = conn.execute(f"""
            SELECT
                id,
                ioc_type,
                indicator,
                source_name,
                confidence,
                severity
            FROM ioc_indicators
            WHERE ioc_type = 'IP'
              AND indicator IN ({placeholders})
              AND is_active = 1
              AND (
                  expires_at_utc IS NULL
                  OR expires_at_utc = ''
                  OR expires_at_utc > ?
              )
            ORDER BY confidence DESC
        """, (*sorted(ips), utc_now())).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_related_alerts(alert_id, window_hours=24):
    """
    Find alerts related through source IP, hostname or username.

    Returns only alerts within the specified time window.
    """

    current = get_alert(alert_id)

    if not current:
        raise ValueError("Alert does not exist.")

    current_time = parse_timestamp(current.get("created_at_utc"))

    if not current_time:
        return []

    window_hours = max(1, min(int(window_hours), 168))

    start = (
        current_time - timedelta(hours=window_hours)
    ).isoformat()

    end = (
        current_time + timedelta(hours=window_hours)
    ).isoformat()

    conditions = []
    params = [alert_id, start, end]

    for field in ("source_ip", "hostname", "username"):

        value = current.get(field)

        if value and str(value).strip() not in ("", "-"):

            conditions.append(f"{field} = ?")
            params.append(value)

    if not conditions:
        return []

    query = f"""
        SELECT *
        FROM alerts
        WHERE id != ?
          AND created_at_utc >= ?
          AND created_at_utc <= ?
          AND (
              {" OR ".join(conditions)}
          )
        ORDER BY created_at_utc DESC
    """

    conn = get_connection()

    try:
        rows = conn.execute(query, params).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def calculate_alert_risk(alert_id, save=True):
    """
    Calculate explainable risk for an alert.

    This is a heuristic prioritization score, not an attack probability.
    """

    alert = get_alert(alert_id)

    if not alert:
        raise ValueError("Alert does not exist.")

    score = 0
    factors = []

    severity = str(alert.get("severity") or "INFO").upper()

    severity_points = SEVERITY_POINTS.get(severity, 0)

    score += severity_points

    factors.append({
        "factor": "Alert severity",
        "points": severity_points,
        "reason": f"Alert severity is {severity}.",
    })

    # ---------------------------------------------
    # IOC MATCHING
    # ---------------------------------------------

    ioc_matches = get_ioc_matches(alert_id)

    if ioc_matches:

        score += 25

        sources = sorted({
            match["source_name"]
            for match in ioc_matches
            if match.get("source_name")
        })

        factors.append({
            "factor": "Known threat intelligence IOC",
            "points": 25,
            "reason": (
                f"{len(ioc_matches)} active IOC record(s) "
                f"matched across sources: {', '.join(sources) or 'Unknown'}."
            ),
        })

    else:

        factors.append({
            "factor": "Known threat intelligence IOC",
            "points": 0,
            "reason": "No active exact IP IOC match was found in linked events.",
        })

    # ---------------------------------------------
    # ALERT CORRELATION
    # ---------------------------------------------

    related_alerts = get_related_alerts(alert_id)

    related_ids = [
        item["id"]
        for item in related_alerts
    ]

    if len(related_alerts) >= 2:

        score += 15

        reason = (
            f"{len(related_alerts)} related alert(s) found "
            "using matching source IP, hostname or username "
            "within the correlation window."
        )

    else:

        reason = (
            f"{len(related_alerts)} related alert(s) found; "
            "at least two are required for this scoring factor."
        )

    factors.append({
        "factor": "Repeated related alerts",
        "points": 15 if len(related_alerts) >= 2 else 0,
        "reason": reason,
    })

    # ---------------------------------------------
    # EVENT VOLUME
    # ---------------------------------------------

    event_count = int(alert.get("event_count") or 0)

    if event_count >= 10:
        volume_points = 10

    elif event_count >= 5:
        volume_points = 5

    else:
        volume_points = 0

    score += volume_points

    factors.append({
        "factor": "Event volume",
        "points": volume_points,
        "reason": f"Alert contains {event_count} event(s).",
    })

    # ---------------------------------------------
    # MITRE MAPPING
    # ---------------------------------------------

    mitre = (
        alert.get("mitre_technique")
        or alert.get("mitre_tactic")
    )

    mitre_points = 5 if mitre else 0

    score += mitre_points

    factors.append({
        "factor": "MITRE ATT&CK mapping",
        "points": mitre_points,
        "reason": (
            "MITRE mapping is available."
            if mitre
            else "No MITRE mapping is recorded."
        ),
    })

    score = min(score, 100)

    risk_level = classify_risk(score)

    result = {
        "alert_id": alert_id,
        "rule_id": alert.get("rule_id"),
        "rule_name": alert.get("rule_name"),
        "severity": severity,
        "risk_score": score,
        "risk_level": risk_level,
        "ioc_matches": ioc_matches,
        "related_alerts": related_alerts,
        "related_alert_ids": related_ids,
        "factors": factors,
        "assessed_at_utc": utc_now(),
    }

    if save:

        conn = get_connection()

        try:

            conn.execute("""
                INSERT INTO alert_risk_assessments (
                    alert_id,
                    risk_score,
                    risk_level,
                    factors_json,
                    related_alert_ids_json,
                    assessed_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                alert_id,
                score,
                risk_level,
                json.dumps(factors),
                json.dumps(related_ids),
                result["assessed_at_utc"],
            ))

            conn.commit()

        finally:
            conn.close()

    return result


def assess_all_alerts():
    """Calculate and store risk scores for all alerts."""

    alerts = get_all_alerts()

    results = []

    for alert in alerts:

        result = calculate_alert_risk(
            alert["id"],
            save=True,
        )

        results.append(result)

    return sorted(
        results,
        key=lambda item: item["risk_score"],
        reverse=True,
    )


def get_latest_risk_assessments(limit=200):
    """Retrieve the latest risk assessment for each alert."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                r.*,
                a.rule_id,
                a.rule_name,
                a.severity,
                a.status,
                a.hostname,
                a.username,
                a.source_ip
            FROM alert_risk_assessments r
            JOIN (
                SELECT alert_id, MAX(id) AS latest_id
                FROM alert_risk_assessments
                GROUP BY alert_id
            ) latest
                ON latest.latest_id = r.id
            JOIN alerts a
                ON a.id = r.alert_id
            ORDER BY r.risk_score DESC, r.id DESC
            LIMIT ?
        """, (max(1, min(int(limit), 1000)),)).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_risk_summary():
    """Return latest risk distribution and summary metrics."""

    assessments = get_latest_risk_assessments(limit=1000)

    distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for item in assessments:

        level = item["risk_level"]

        if level in distribution:
            distribution[level] += 1

    return {
        "total_assessed": len(assessments),
        "average_score": (
            round(
                sum(item["risk_score"] for item in assessments)
                / len(assessments),
                2,
            )
            if assessments else 0
        ),
        "high_and_critical": (
            distribution["HIGH"] + distribution["CRITICAL"]
        ),
        "distribution": distribution,
        "assessments": assessments,
    }
