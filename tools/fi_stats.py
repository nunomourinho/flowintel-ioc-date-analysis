#!/usr/bin/env python3
"""Date statistics of IoCs as stored by Flowintel (read-only query on its PostgreSQL DB).

Source = case title prefix [Fnnn] set by fi_import_feeds.py; other cases = "Bundled test data".
Needs psycopg2 (Flowintel venv). Output: flowintel_stats.json.
"""
import collections
import json
import os
import re
import sys

import psycopg2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fi_raw_stats import Acc  # noqa: E402

SQL = """
SELECT c.title, a.type, a.first_seen, a.last_seen, a.ids_flag, (a.case_misp_object_id IS NOT NULL)
FROM misp__attribute a
LEFT JOIN case__misp__object o ON o.id = a.case_misp_object_id
JOIN "case" c ON c.id = COALESCE(a.case_id, o.case_id)
"""


def main():
    conn = psycopg2.connect(dbname=os.getenv("DB_NAME", "flowintel"), user=os.getenv("DB_USER", "flowintel"),
                            password=os.getenv("DB_PASSWORD"), host=os.getenv("DB_HOST", "localhost"))
    conn.set_session(readonly=True)
    cur = conn.cursor(name="attrs")
    cur.itersize = 20000
    cur.execute(SQL)
    accs = collections.defaultdict(Acc)
    extra = collections.defaultdict(collections.Counter)
    for title, typ, fs, ls, ids, in_obj in cur:
        m = re.match(r"\[F(\d{3})\]", title or "")
        key = int(m.group(1)) if m else -1
        accs[key].add(typ, fs.isoformat() if fs else None, ls.isoformat() if ls else None)
        extra[key]["ids_flag"] += bool(ids)
        extra[key]["in_objects"] += bool(in_obj)
    c2 = conn.cursor()
    c2.execute('SELECT title FROM "case"')
    cases = collections.Counter()
    for (t,) in c2.fetchall():
        m = re.match(r"\[F(\d{3})\]", t or "")
        cases[int(m.group(1)) if m else -1] += 1
    c2.execute("SELECT count(*) FROM case__misp__object")
    n_obj = c2.fetchone()[0]
    out = {str(k): {"cases": cases[k], **accs[k].out(), **extra[k]} for k in sorted(set(accs) | set(cases))}
    out["_totals"] = {"cases": sum(cases.values()), "objects": n_obj,
                      "attributes": sum(a.n for a in accs.values())}
    json.dump(out, open("flowintel_stats.json", "w"), indent=1, default=str)
    print(json.dumps(out["_totals"]))


if __name__ == "__main__":
    main()
