"""
Shared pytest fixtures for TRACE-SOC tests.

test_db  — provides an isolated in-memory SQLite database for every test
           that requests the fixture. It patches database.db.DATABASE_PATH
           so all engine modules write to the temp file, not the real DB.
"""

import pytest
from pathlib import Path
import database.db as db
from database.db import create_tables
from investigation.story_schema import create_story_tables
from dashboard.data_access import ensure_dashboard_schema


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Isolated SQLite database for one test."""
    temp_db = tmp_path / "tracesoc_test.db"
    monkeypatch.setattr(db, "DATABASE_PATH", temp_db)

    # Bootstrap core schema so all modules have their tables
    create_tables()
    create_story_tables()
    ensure_dashboard_schema()

    yield temp_db
