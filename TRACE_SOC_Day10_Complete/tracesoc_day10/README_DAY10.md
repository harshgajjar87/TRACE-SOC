# TRACE-SOC Day 10 — Attack Investigation & Reconstruction

## Files
Copy the `investigation` folder into your project, replacing `story_schema.py` and `story_builder.py` with the included updated versions. Keep your existing `correlation.py` and `database/db.py` unchanged.

New modules:
- `investigation/timeline.py`: chronological observed-event timeline plus separately displayed inferred relationship edges.
- `investigation/evidence.py`: raw XML evidence inventory and SHA-256 verification.
- `investigation/investigation_queries.py`: list/search/get full investigations.

Updated modules:
- `story_schema.py`: adds `story_relationships`, `story_alert_links`, and `raw_events.raw_xml_sha256` with a safe SQLite migration/backfill.
- `story_builder.py`: supports both `normalized_event_ids` and legacy `event_ids` in alert evidence JSON; stores all story-alert links and correlation explanations; remains idempotent.

## Important evidence-hash distinction
`raw_events.source_file_sha256` is the hash of the original source file. It is NOT the hash of each `raw_xml` event BLOB. This package adds `raw_xml_sha256` for the individual stored XML blob. Existing rows are backfilled from the currently stored BLOB when the migration first runs. This establishes a baseline from migration time; it cannot prove that the BLOB was not changed before that baseline existed. Update your `database/import_events.py` ingestion insert to store `hashlib.sha256(raw_xml_bytes).hexdigest()` in `raw_xml_sha256` for every newly imported event.

## Initialize / run
From `D:\TRACE-SOC`:

```powershell
python -m investigation.story_schema
python -m investigation.story_builder
python -c "from investigation.timeline import print_story_timeline; print_story_timeline(1)"
python -c "from investigation.investigation_queries import list_stories; [print(x) for x in list_stories()]"
python -c "from investigation.evidence import get_story_evidence, verify_raw_event_integrity; items=get_story_evidence(1); print(items); [print(verify_raw_event_integrity(x['raw_event_id'])) for x in items]"
```

Replace story ID `1` with an ID that exists in your database. If there are no correlated event groups, the builder correctly creates no story.

## APIs
```python
from investigation.timeline import get_story_timeline, print_story_timeline
from investigation.evidence import get_story_evidence, verify_raw_event_integrity
from investigation.investigation_queries import list_stories, search_stories, get_investigation
```

Correlation scores are heuristic relationship-strength scores, not probabilities that an attack occurred. A story is an investigation candidate, not a confirmed incident. Missing telemetry can prevent detection or reconstruction.
