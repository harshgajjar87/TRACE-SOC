import pytest

import database.db as db
from database.db import create_tables
from investigation.story_schema import create_story_tables
from reports.pdf_generator import generate_investigation_pdf


@pytest.fixture
def report_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "report_test.db")
    create_tables()
    create_story_tables()
    con=db.get_connection()
    with con:
        con.execute("INSERT INTO attack_stories (story_fingerprint,title,description,severity,status,event_count,alert_count,confidence_score,confidence_level,created_at_utc) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    ("report-story","PDF test investigation","Synthetic report test","INFO","NEW",0,0,0,"LOW","2026-11-10T10:00:00Z"))
    con.close()


def test_pdf_report_is_generated(report_db):
    payload = generate_investigation_pdf(1)
    assert payload.startswith(b"%PDF-")
    assert len(payload) > 500
