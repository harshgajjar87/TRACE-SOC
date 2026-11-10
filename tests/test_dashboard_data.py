import sqlite3
import pytest

import database.db as db
from database.db import create_tables
from investigation.story_schema import create_story_tables
from dashboard.data_access import (ensure_dashboard_schema, get_dashboard_summary, get_alerts,
    update_alert_status, get_alert_status_history, get_stories, search_events)


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "dashboard_test.db")
    create_tables()
    create_story_tables()
    ensure_dashboard_schema()
    con=db.get_connection()
    with con:
        con.execute("INSERT INTO raw_events (event_fingerprint,source_file,source_file_sha256,raw_xml,event_id,provider,channel,record_id,timestamp_utc,hostname,collected_at_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    ("fp1","event.xml","abc",b"<Event/>","4625","Microsoft-Windows-Security-Auditing","Security","1","2026-11-10T10:00:00Z","LAB-PC","2026-11-10T10:00:00Z"))
        con.execute("INSERT INTO normalized_events (raw_event_id,event_id,provider,channel,timestamp_utc,hostname,username,source_ip,event_type,extra_data_json) VALUES (1,'4625','Microsoft-Windows-Security-Auditing','Security','2026-11-10T10:00:00Z','LAB-PC','alice','192.0.2.10','authentication_failure','{}')")
        con.execute("INSERT INTO alerts (alert_fingerprint,rule_id,rule_name,description,severity,status,hostname,username,source_ip,first_seen,last_seen,event_count,mitre_tactic,mitre_technique,evidence_json,created_at_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    ("afp1","TS001","Repeated Failed Logins","Test alert","HIGH","NEW","LAB-PC","alice","192.0.2.10","2026-11-10T10:00:00Z","2026-11-10T10:00:00Z",1,"Credential Access","T1110",'{"normalized_event_ids":[1]}',"2026-11-10T10:01:00Z"))
        con.execute("INSERT INTO attack_stories (story_fingerprint,title,description,severity,status,hostname,username,source_ip,first_seen,last_seen,event_count,alert_count,confidence_score,confidence_level,created_at_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    ("sfp1","Test investigation","Synthetic test","HIGH","NEW","LAB-PC","alice","192.0.2.10","2026-11-10T10:00:00Z","2026-11-10T10:00:00Z",1,1,90,"HIGH","2026-11-10T10:02:00Z"))
    con.close()
    return tmp_path / "dashboard_test.db"


def test_dashboard_summary_and_filters(isolated_db):
    summary=get_dashboard_summary()
    assert summary["counts"]["total_events"]==1
    assert summary["counts"]["total_alerts"]==1
    assert summary["counts"]["open_alerts"]==1
    assert summary["counts"]["total_stories"]==1
    assert len(get_alerts(status="NEW",severity="HIGH",search="alice"))==1
    assert get_alerts(status="RESOLVED")==[]
    assert len(get_stories(status="NEW",severity="HIGH",search="LAB-PC"))==1


def test_alert_status_update_is_audited(isolated_db):
    assert update_alert_status(1,"INVESTIGATING","Analyst started triage") is True
    assert get_alerts()[0]["status"]=="INVESTIGATING"
    history=get_alert_status_history(1)
    assert len(history)==1
    assert history[0]["old_status"]=="NEW"
    assert history[0]["new_status"]=="INVESTIGATING"
    assert history[0]["note"]=="Analyst started triage"
    assert update_alert_status(1,"INVESTIGATING") is True
    assert len(get_alert_status_history(1))==1


def test_status_validation_and_missing_alert(isolated_db):
    with pytest.raises(ValueError): update_alert_status(1,"CLOSED")
    assert update_alert_status(999,"RESOLVED") is False


def test_threat_hunting_filters(isolated_db):
    rows=search_events(hostname="LAB-PC",username="alice",source_ip="192.0.2.10",event_id="4625")
    assert len(rows)==1
    assert rows[0]["event_type"]=="authentication_failure"
    assert search_events(hostname="OTHER")==[]
