#!/usr/bin/env python3
"""Native date statistics computed directly from the downloaded feed content (no caps).

MISP feeds: per attribute (standalone + inside objects) presence of first_seen/last_seen,
object-level first_seen/last_seen, and date-typed object attributes (first-seen/last-seen relations).
CSV/freetext feeds: date-like columns/tokens per data row.
Output: raw_stats.json (one record per source).
"""
import collections
import json
import os
import re
import statistics
import sys
from datetime import datetime, timezone

DATE_RE = re.compile(r"\b(19|20)\d\d-[01]\d-[0-3]\d([ T][0-2]\d:[0-5]\d(:[0-5]\d)?)?")
ISO_FMT = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
           "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


def parse(v):
    if v in (None, "", 0):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
        try:
            return datetime.fromtimestamp(int(v), timezone.utc)
        except (ValueError, OverflowError):
            return None
    v = str(v).replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(v)
    except ValueError:
        d = None
        for f in ISO_FMT:
            try:
                d = datetime.strptime(v, f)
                break
            except ValueError:
                pass
    if d and d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))] if xs else None


class Acc:
    def __init__(self):
        self.n = 0
        self.fs = self.ls = self.both = self.neither = self.inverted = 0
        self.fs_min = self.fs_max = self.ls_min = self.ls_max = None
        self.durs = []
        self.types = collections.Counter()
        self.fs_years = collections.Counter()

    def add(self, typ, fs, ls):
        self.n += 1
        self.types[typ] += 1
        f, l = parse(fs), parse(ls)
        if f:
            self.fs += 1
            self.fs_years[f.year] += 1
            self.fs_min = min(self.fs_min or f, f)
            self.fs_max = max(self.fs_max or f, f)
        if l:
            self.ls += 1
            self.ls_min = min(self.ls_min or l, l)
            self.ls_max = max(self.ls_max or l, l)
        if f and l:
            self.both += 1
            d = (l - f).total_seconds() / 86400
            if d < 0:
                self.inverted += 1
            self.durs.append(d)
        if not f and not l:
            self.neither += 1

    def out(self):
        iso = lambda d: d.isoformat()[:19] if d else None
        pos = [d for d in self.durs if d >= 0]
        return {"attributes": self.n, "first_seen": self.fs, "last_seen": self.ls, "both": self.both,
                "neither": self.neither, "first_only": self.fs - self.both, "last_only": self.ls - self.both,
                "inverted": self.inverted, "fs_min": iso(self.fs_min), "fs_max": iso(self.fs_max),
                "ls_min": iso(self.ls_min), "ls_max": iso(self.ls_max),
                "dur_days_median": round(statistics.median(pos), 2) if pos else None,
                "dur_days_mean": round(statistics.mean(pos), 2) if pos else None,
                "dur_days_p90": round(pct(pos, 90), 2) if pos else None,
                "dur_days_max": round(max(pos), 2) if pos else None,
                "dur_zero": sum(1 for d in pos if d == 0),
                "types_top": self.types.most_common(8), "fs_years": dict(sorted(self.fs_years.items()))}


def misp_stats(p):
    acc = Acc()
    obj = collections.Counter()
    ev_dates = []
    evdir = os.path.join(p, "events")
    n_ev = 0
    for f in os.listdir(evdir) if os.path.isdir(evdir) else []:
        try:
            ev = json.load(open(os.path.join(evdir, f)))
        except ValueError:
            continue
        e = ev.get("Event", ev)
        n_ev += 1
        d = parse(e.get("date"))
        if d:
            ev_dates.append(d)
        for a in e.get("Attribute") or []:
            acc.add(a.get("type"), a.get("first_seen"), a.get("last_seen"))
        for o in e.get("Object") or []:
            obj["objects"] += 1
            obj["obj_first_seen"] += bool(o.get("first_seen"))
            obj["obj_last_seen"] += bool(o.get("last_seen"))
            for a in o.get("Attribute") or []:
                acc.add(a.get("type"), a.get("first_seen"), a.get("last_seen"))
                rel = (a.get("object_relation") or "").lower()
                if rel in ("first-seen", "first_seen", "firstseen"):
                    obj["rel_first_seen"] += 1
                elif rel in ("last-seen", "last_seen", "lastseen"):
                    obj["rel_last_seen"] += 1
    r = {"events": n_ev, **acc.out(), **{k: obj[k] for k in
         ("objects", "obj_first_seen", "obj_last_seen", "rel_first_seen", "rel_last_seen")}}
    r["event_date_min"] = min(ev_dates).date().isoformat() if ev_dates else None
    r["event_date_max"] = max(ev_dates).date().isoformat() if ev_dates else None
    return r


def text_stats(p):
    b = open(os.path.join(p, "raw"), "rb").read()
    if not b.strip() or b[:512].lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return {"unusable": "empty response" if not b.strip() else "HTML page instead of feed data", "bytes": len(b)}
    raw = b.decode("utf-8", "replace")
    rows = [l for l in raw.splitlines() if l.strip() and not l.lstrip().startswith(("#", "//", ";"))]
    with_dates = collections.Counter()
    for l in rows:
        with_dates[min(len(DATE_RE.findall(l)), 2)] += 1
    header = [l for l in raw.splitlines()[:15] if l.lstrip().startswith("#")]
    return {"data_rows": len(rows), "rows_0_dates": with_dates[0], "rows_1_date": with_dates[1],
            "rows_2plus_dates": with_dates[2], "bytes": len(raw), "header_sample": header[:6],
            "first_row_sample": rows[0][:200] if rows else None}


def main():
    feeds = sys.argv[1]
    out = []
    for d in sorted(os.listdir(feeds)):
        p = os.path.join(feeds, d)
        meta = json.load(open(os.path.join(p, "meta.json")))
        fetch = json.load(open(os.path.join(p, "fetch.json")))
        rec = {"idx": int(d), "name": meta["name"], "provider": meta["provider"], "format": meta["source_format"],
               "url": meta["url"], "fetch": fetch}
        if fetch.get("status") == "ok":
            try:
                rec["native"] = misp_stats(p) if meta["source_format"] == "misp" else text_stats(p)
            except Exception as e:
                rec["native_error"] = repr(e)[:300]
        out.append(rec)
        print(d, meta["name"][:50], json.dumps(rec.get("native", {}))[:160], flush=True)
    json.dump(out, open("raw_stats.json", "w"), indent=1)


if __name__ == "__main__":
    main()
