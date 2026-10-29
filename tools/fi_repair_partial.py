#!/usr/bin/env python3
"""Find cases left incomplete by HTTP 500 during import (values > varchar(255)), delete them through
the API and re-create them. Run after `ALTER TABLE misp__attribute ALTER COLUMN value TYPE text`.
Writes repair_log.jsonl (one record per re-created case). Needs psycopg2 (Flowintel venv).
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import uuid as uuidlib

import psycopg2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fi_import_feeds import API, iocs_from_raw, is_html  # noqa: E402

COUNT_SQL = """
SELECT c.id, c.title,
  (SELECT count(*) FROM misp__attribute a WHERE a.case_id = c.id)
  + (SELECT count(*) FROM misp__attribute a JOIN case__misp__object o ON o.id = a.case_misp_object_id
     WHERE o.case_id = c.id)
FROM "case" c WHERE c.title LIKE %s
"""


def expected_cases(p, idx, meta, chunk):
    """Yield (title, event_json, n_attrs) exactly as fi_import_feeds.py builds them."""
    tag = f"[F{idx:03d}]"
    if meta["source_format"] == "misp":
        evdir = os.path.join(p, "events")
        for f in sorted(os.listdir(evdir)):
            ev = json.load(open(os.path.join(evdir, f)))
            if "Event" not in ev:
                ev = {"Event": ev}
            e = ev["Event"]
            n = len(e.get("Attribute") or []) + sum(len(o.get("Attribute") or []) for o in e.get("Object") or [])
            yield f"{tag} {(e.get('info') or f)[:180]} [{f[:8]}]", ev, n
    else:
        raw = open(os.path.join(p, "raw"), "rb").read()
        if is_html(raw):
            return
        iocs = iocs_from_raw(raw, meta)
        chunks = [iocs[i:i + chunk] for i in range(0, len(iocs), chunk)]
        for n, part in enumerate(chunks, 1):
            suffix = f" (part {n}/{len(chunks)})" if len(chunks) > 1 else ""
            ev = {"Event": {"uuid": str(uuidlib.uuid4()), "info": meta["name"], "date": time.strftime("%Y-%m-%d"),
                            "Attribute": [{"uuid": str(uuidlib.uuid4()), "type": t, "value": v,
                                           "category": "Network activity", "to_ids": True} for t, v in part]}}
            yield f"{tag} {meta['name'][:160]}{suffix}", ev, len(part)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("feeds")
    ap.add_argument("--url", default="http://127.0.0.1:7006")
    ap.add_argument("--key", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--chunk", type=int, default=50000)
    ap.add_argument("--log", default="repair_log.jsonl")
    args = ap.parse_args()
    api = API(args.url, args.key)
    conn = psycopg2.connect(dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
                            password=os.getenv("DB_PASSWORD"), host=os.getenv("DB_HOST", "localhost"))
    conn.autocommit = True
    only = {int(x) for x in args.only.split(",") if x}
    log = open(args.log, "a")
    for d in sorted(os.listdir(args.feeds)):
        idx = int(d)
        if only and idx not in only:
            continue
        p = os.path.join(args.feeds, d)
        meta = json.load(open(os.path.join(p, "meta.json")))
        if json.load(open(os.path.join(p, "fetch.json"))).get("status") != "ok":
            continue
        cur = conn.cursor()
        cur.execute(COUNT_SQL, (f"[F{idx:03d}]%",))
        have = {t: (cid, n) for cid, t, n in cur.fetchall()}
        for title, ev, n in expected_cases(p, idx, meta, args.chunk):
            cid, got = have.get(title, (None, 0))
            if cid and got == n:
                continue
            if cid:
                req = urllib.request.Request(f"{api.url}/api/case/{cid}/delete", headers={"X-API-KEY": api.key})
                urllib.request.urlopen(req, timeout=600).read()
            st, r = api.create(title, ev, f"Imported from feed: {meta['name']} ({meta['url']})")
            rec = {"idx": idx, "title": title[:120], "expected": n, "had": got, "deleted_case": cid, "status": st,
                   "message": str(r.get("message"))[:200]}
            log.write(json.dumps(rec) + "\n")
            log.flush()
        print(json.dumps({"idx": idx, "done": True}), flush=True)


if __name__ == "__main__":
    main()
