
"""TRACE-SOC SOC analytics engine."""

from datetime import date, datetime, timedelta, timezone

from database.db import get_connection


def _parse_timestamp(value):
    """Parse an ISO timestamp into a timezone-aware datetime."""

    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def _in_date_range(value, start_date=None, end_date=None):
    """Check whether a timestamp falls within the selected date range."""

    parsed = _parse_timestamp(value)

    if parsed is None:
        return False

    if start_date and parsed.date() < start_date:
        return False

    if end_date and parsed.date() > end_date:
        return False

    return True


def _get_alert_records():
    """Retrieve alert records."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                id,
                rule_id,
                rule_name,
                severity,
                status,
                hostname,
                username,
                source_ip,
                first_seen,
                last_seen,
                created_at_utc
            FROM alerts
            ORDER BY id
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def _get_case_records():
    """Retrieve incident case records."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                id,
                case_number,
                title,
                status,
                priority,
                assigned_to,
                created_by,
                created_at_utc,
                resolved_at_utc,
                closed_at_utc
            FROM incident_cases
            ORDER BY id
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_soc_kpis(start_date=None, end_date=None):
    """
    Calculate headline SOC metrics.

    Alert metrics are filtered using alert creation date.
    Case metrics are filtered using case creation date.
    """

    alerts = [
        alert for alert in _get_alert_records()
        if _in_date_range(
            alert["created_at_utc"],
            start_date,
            end_date,
        )
    ]

    cases = [
        case for case in _get_case_records()
        if _in_date_range(
            case["created_at_utc"],
            start_date,
            end_date,
        )
    ]

    open_alerts = [
        alert for alert in alerts
        if alert["status"] in ("NEW", "INVESTIGATING")
    ]

    critical_alerts = [
        alert for alert in alerts
        if alert["severity"] == "CRITICAL"
    ]

    open_cases = [
        case for case in cases
        if case["status"] not in ("RESOLVED", "CLOSED")
    ]

    resolved_cases = [
        case for case in cases
        if case["resolved_at_utc"]
    ]

    mttd_values = []

    for alert in alerts:

        first_seen = _parse_timestamp(alert["first_seen"])
        created = _parse_timestamp(alert["created_at_utc"])

        if first_seen and created:

            seconds = (created - first_seen).total_seconds()

            if seconds >= 0:
                mttd_values.append(seconds)

    mttr_values = []

    for case in resolved_cases:

        created = _parse_timestamp(case["created_at_utc"])
        resolved = _parse_timestamp(case["resolved_at_utc"])

        if created and resolved:

            seconds = (resolved - created).total_seconds()

            if seconds >= 0:
                mttr_values.append(seconds)

    return {
        "total_alerts": len(alerts),
        "open_alerts": len(open_alerts),
        "critical_alerts": len(critical_alerts),
        "total_cases": len(cases),
        "open_cases": len(open_cases),
        "resolved_cases": len(resolved_cases),
        "mttd_seconds": (
            sum(mttd_values) / len(mttd_values)
            if mttd_values else None
        ),
        "mttr_seconds": (
            sum(mttr_values) / len(mttr_values)
            if mttr_values else None
        ),
        "mttd_sample_count": len(mttd_values),
        "mttr_sample_count": len(mttr_values),
    }


def get_alert_trend(days=30):
    """Return daily alert counts for the requested number of days."""

    days = max(1, min(int(days), 365))

    alerts = _get_alert_records()

    today = datetime.now(timezone.utc).date()
    first_day = today - timedelta(days=days - 1)

    counts = {}

    for offset in range(days):

        current_day = first_day + timedelta(days=offset)

        counts[current_day.isoformat()] = 0

    for alert in alerts:

        created = _parse_timestamp(alert["created_at_utc"])

        if created:

            day = created.date().isoformat()

            if day in counts:
                counts[day] += 1

    return [
        {
            "date": day,
            "alert_count": count,
        }
        for day, count in counts.items()
    ]


def get_severity_distribution():
    """Return alert counts grouped by severity."""

    alerts = _get_alert_records()

    distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for alert in alerts:

        severity = alert["severity"]

        if severity in distribution:
            distribution[severity] += 1

    return [
        {
            "severity": severity,
            "count": count,
        }
        for severity, count in distribution.items()
    ]


def get_case_status_distribution():
    """Return case counts grouped by status."""

    cases = _get_case_records()

    statuses = {
        "OPEN": 0,
        "IN_PROGRESS": 0,
        "ESCALATED": 0,
        "RESOLVED": 0,
        "CLOSED": 0,
    }

    for case in cases:

        status = case["status"]

        if status in statuses:
            statuses[status] += 1

    return [
        {
            "status": status,
            "count": count,
        }
        for status, count in statuses.items()
    ]


def get_analyst_workload():
    """Calculate assigned and resolved cases per analyst."""

    cases = _get_case_records()

    workload = {}

    for case in cases:

        analyst = case["assigned_to"] or "Unassigned"

        if analyst not in workload:

            workload[analyst] = {
                "analyst": analyst,
                "assigned_cases": 0,
                "resolved_cases": 0,
            }

        workload[analyst]["assigned_cases"] += 1

        if case["resolved_at_utc"]:
            workload[analyst]["resolved_cases"] += 1

    return sorted(
        workload.values(),
        key=lambda item: item["assigned_cases"],
        reverse=True,
    )


def get_mttd_mttr_trend(days=30):
    """
    Return daily average MTTD and MTTR.

    MTTD uses alert first_seen to alert created_at_utc.
    MTTR uses case created_at_utc to resolved_at_utc.
    """

    days = max(1, min(int(days), 365))

    today = datetime.now(timezone.utc).date()
    first_day = today - timedelta(days=days - 1)

    daily = {}

    for offset in range(days):

        current_day = first_day + timedelta(days=offset)

        daily[current_day.isoformat()] = {
            "date": current_day.isoformat(),
            "mttd_seconds": [],
            "mttr_seconds": [],
        }

    for alert in _get_alert_records():

        first_seen = _parse_timestamp(alert["first_seen"])
        created = _parse_timestamp(alert["created_at_utc"])

        if not first_seen or not created:
            continue

        seconds = (created - first_seen).total_seconds()

        if seconds < 0:
            continue

        day = created.date().isoformat()

        if day in daily:
            daily[day]["mttd_seconds"].append(seconds)

    for case in _get_case_records():

        created = _parse_timestamp(case["created_at_utc"])
        resolved = _parse_timestamp(case["resolved_at_utc"])

        if not created or not resolved:
            continue

        seconds = (resolved - created).total_seconds()

        if seconds < 0:
            continue

        day = resolved.date().isoformat()

        if day in daily:
            daily[day]["mttr_seconds"].append(seconds)

    results = []

    for item in daily.values():

        mttd = item["mttd_seconds"]
        mttr = item["mttr_seconds"]

        results.append({
            "date": item["date"],
            "mttd_seconds": (
                sum(mttd) / len(mttd)
                if mttd else None
            ),
            "mttr_seconds": (
                sum(mttr) / len(mttr)
                if mttr else None
            ),
            "mttd_samples": len(mttd),
            "mttr_samples": len(mttr),
        })

    return results


def format_duration(seconds):
    """Format a duration in seconds into a readable value."""

    if seconds is None:
        return "N/A"

    seconds = max(0, int(seconds))

    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, remaining_seconds = divmod(remainder, 60)

    if days:
        return f"{days}d {hours}h"

    if hours:
        return f"{hours}h {minutes}m"

    if minutes:
        return f"{minutes}m {remaining_seconds}s"

    return f"{remaining_seconds}s"
