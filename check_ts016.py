import sqlite3

c = sqlite3.connect('data/tracesoc.db')

print('TS016 alerts:', c.execute("SELECT COUNT(*) FROM alerts WHERE rule_id='TS016'").fetchone()[0])
print('TS016 stories:', c.execute("SELECT COUNT(*) FROM attack_stories WHERE title LIKE '%TS016%' OR title LIKE '%Special Privileges%'").fetchone()[0])

print()
for r in c.execute("SELECT id, rule_id, username, created_at_utc FROM alerts WHERE rule_id='TS016' ORDER BY id DESC LIMIT 10"):
    print(r)

c.close()
