import sqlite3, json

c = sqlite3.connect('data/tracesoc.db')
c.row_factory = sqlite3.Row

total = c.execute("SELECT COUNT(*) FROM alerts WHERE rule_id='TS002'").fetchone()[0]
print(f"Total TS002 alerts: {total}\n")

alerts = c.execute("""
    SELECT id, username, hostname, created_at_utc, evidence_json
    FROM alerts WHERE rule_id='TS002'
    ORDER BY id DESC LIMIT 10
""").fetchall()

for a in alerts:
    ev = json.loads(a['evidence_json'])
    ev_id = ev['normalized_event_ids'][0] if ev['normalized_event_ids'] else None
    keywords = ev.get('matched_keywords', [])

    print(f"Alert {a['id']} | user={a['username']} | host={a['hostname']} | {a['created_at_utc']}")
    print(f"  matched_keywords : {keywords}")

    if ev_id:
        row = c.execute("SELECT * FROM normalized_events WHERE id=?", (ev_id,)).fetchone()
        if row:
            extra = json.loads(row['extra_data_json'] or '{}')
            print(f"  timestamp        : {row['timestamp_utc']}")
            print(f"  image            : {row['image']}")
            print(f"  command_line     : {row['command_line']}")
            print(f"  parent_image     : {extra.get('ParentImage')}")
            print(f"  parent_cmdline   : {extra.get('ParentCommandLine')}")
            print(f"  user             : {extra.get('User')}")
    print()

c.close()
