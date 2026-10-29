#!/usr/bin/env python3
"""Import downloaded feeds into Flowintel through POST /api/case/create_with_event.

MISP feeds: each event JSON is sent as-is (first_seen/last_seen preserved by Flowintel).
CSV/freetext feeds: IoCs are extracted the way MISP's feed parser does (value column(s) or
free-text regex), packed into one MISP event per feed. MISP does not map dates from CSV feeds,
so these attributes carry no first_seen/last_seen.

Caps (per source, documented in the report): --max-events, --max-attrs.
Writes import_log.jsonl.
"""
import argparse
import csv
import io
import ipaddress
import json
import os
import re
import time
import urllib.request
import uuid as uuidlib

RE_URL = re.compile(r"^(?:h..ps?|ftp)://\S+", re.I)
RE_MD5 = re.compile(r"^[a-f0-9]{32}$", re.I)
RE_SHA1 = re.compile(r"^[a-f0-9]{40}$", re.I)
RE_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.I)
RE_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$", re.I)
RE_BTC = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def _is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def is_html(raw):
    head = raw[:512].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def guess_type(v, default=None):
    v = v.strip().strip('"')
    if not v:
        return None, None
    if RE_URL.match(v):
        return "url", v
    if RE_SHA256.match(v):
        return "sha256", v.lower()
    if RE_SHA1.match(v):
        return "sha1", v.lower()
    if RE_MD5.match(v):
        return "md5", v.lower()
    if RE_CVE.match(v):
        return "vulnerability", v.upper()
    if "/" in v:
        h, path = v.split("/", 1)
        h = h.split(":")[0]
        if not path.isdigit() and (RE_DOMAIN.match(h) or _is_ip(h)):
            return "url", v  # scheme-less URL, as MISP's freetext parser detects it
    host = v.split(":")[0] if v.count(":") == 1 else v
    try:
        if "/" in host:
            ipaddress.ip_network(host, strict=False)
        else:
            ipaddress.ip_address(host)
        return default or "ip-dst", v
    except ValueError:
        pass
    if RE_DOMAIN.match(v):
        return "domain", v.lower()
    if RE_BTC.match(v):
        return "btc", v
    return None, None


def load_settings(meta):
    s = meta.get("settings") or {}
    if isinstance(s, str):
        try:
            s = json.loads(s)
            if isinstance(s, str):
                s = json.loads(s)
        except ValueError:
            s = {}
    return s


def iocs_from_raw(raw, meta):
    """Return list of (type, value). Mirrors MISP Feed::getFreetextFeed / CSV parsing."""
    s = load_settings(meta)
    csvs = s.get("csv") or {}
    common = s.get("common") or {}
    default_type = common.get("defaultType")
    excl = common.get("excluderegex") or ""
    excl_re = None
    if excl:
        m = re.match(r"^/(.*)/([a-z]*)$", excl.replace("\\/", "/"))
        try:
            excl_re = re.compile(m.group(1), re.I if "i" in m.group(2) else 0) if m else re.compile(excl)
        except re.error:
            excl_re = None
    text = raw.decode("utf-8", "replace")
    out, seen = [], set()

    def add(v):
        t, val = guess_type(v, default_type)
        if t and (t, val) not in seen and not (excl_re and excl_re.search(val)):
            seen.add((t, val))
            out.append((t, val))

    if meta["source_format"] == "csv" and (csvs.get("value") or "").strip():
        cols = [int(c) - 1 for c in str(csvs["value"]).split(",") if c.strip().isdigit()]
        delim = csvs.get("delimiter") or ","
        if delim == "\\t":
            delim = "\t"
        lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        for row in csv.reader(lines, delimiter=delim[0], skipinitialspace=True):
            for c in cols:
                if c < len(row):
                    add(row[c])
    else:
        # freetext: every token on non-comment lines
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "//", ";")):
                continue
            for tok in re.split(r"[\s,;|]+", line):
                add(tok)
    return out


class API:
    def __init__(self, url, key):
        self.url, self.key = url.rstrip("/"), key

    def create(self, title, event, description=""):
        body = json.dumps({"title": title, "description": description, "event": event}).encode()
        req = urllib.request.Request(self.url + "/api/case/create_with_event", data=body, method="POST",
                                     headers={"X-API-KEY": self.key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=3600) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, {"message": e.read()[:300].decode("utf-8", "replace")}


def trim_event(ev, max_attrs):
    """Keep at most max_attrs attributes (standalone first, then whole objects)."""
    e = ev["Event"]
    attrs = e.get("Attribute") or []
    objs = e.get("Object") or []
    n_total = len(attrs) + sum(len(o.get("Attribute") or []) for o in objs)
    if not max_attrs or n_total <= max_attrs:
        return ev, n_total, n_total
    keep_attrs = attrs[:max_attrs]
    budget = max_attrs - len(keep_attrs)
    keep_objs = []
    for o in objs:
        n = len(o.get("Attribute") or [])
        if n > budget:
            break
        keep_objs.append(o)
        budget -= n
    e = dict(e, Attribute=keep_attrs, Object=keep_objs)
    sent = len(keep_attrs) + sum(len(o.get("Attribute") or []) for o in keep_objs)
    return {"Event": e}, n_total, sent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("feeds")
    ap.add_argument("--url", default="http://127.0.0.1:7006")
    ap.add_argument("--key", required=True)
    ap.add_argument("--max-events", type=int, default=0)
    ap.add_argument("--max-attrs", type=int, default=0, help="per source")
    ap.add_argument("--only", default="")
    ap.add_argument("--chunk", type=int, default=50000, help="IoCs per case for csv/freetext feeds")
    ap.add_argument("--log", default="import_log.jsonl")
    args = ap.parse_args()
    api = API(args.url, args.key)
    only = {int(x) for x in args.only.split(",") if x}
    done = set()
    if os.path.exists(args.log):
        for l in open(args.log):
            done.add(json.loads(l)["idx"])
    log = open(args.log, "a")
    for d in sorted(os.listdir(args.feeds)):
        idx = int(d)
        if (only and idx not in only) or idx in done:
            continue
        p = os.path.join(args.feeds, d)
        meta = json.load(open(os.path.join(p, "meta.json")))
        fetch = json.load(open(os.path.join(p, "fetch.json"))) if os.path.exists(os.path.join(p, "fetch.json")) else {}
        rec = {"idx": idx, "name": meta["name"], "format": meta["source_format"], "cases": 0,
               "attrs_in_source": 0, "attrs_sent": 0, "errors": [], "t0": time.time()}
        tag = f"[F{idx:03d}]"
        if fetch.get("status") != "ok":
            rec["skipped"] = "download failed: " + str(fetch.get("error"))
        elif meta["source_format"] == "misp":
            evdir = os.path.join(p, "events")
            files = sorted(os.listdir(evdir)) if os.path.isdir(evdir) else []
            man = json.load(open(os.path.join(p, "manifest.json")))
            files.sort(key=lambda f: int(man.get(f[:-5], {}).get("timestamp") or 0), reverse=True)
            budget = args.max_attrs
            for n, f in enumerate(files):
                if args.max_events and rec["cases"] >= args.max_events:
                    break
                try:
                    ev = json.load(open(os.path.join(evdir, f)))
                except ValueError as e:
                    rec["errors"].append(f"{f}: bad json")
                    continue
                if "Event" not in ev:
                    ev = {"Event": ev}
                if args.max_attrs and budget <= 0:
                    break
                ev, total, sent = trim_event(ev, budget if args.max_attrs else 0)
                info = (ev["Event"].get("info") or f)[:180]
                st, r = api.create(f"{tag} {info} [{f[:8]}]", ev, f"Imported from feed: {meta['name']} ({meta['url']})")
                if st == 201:
                    rec["cases"] += 1
                    rec["attrs_sent"] += sent
                    rec["attrs_in_source"] += total
                    budget -= sent
                else:
                    rec["errors"].append(f"{f}: {st} {r.get('message')}"[:200])
        else:
            raw = open(os.path.join(p, "raw"), "rb").read()
            iocs = [] if is_html(raw) else iocs_from_raw(raw, meta)
            rec["attrs_in_source"] = len(iocs)
            if args.max_attrs:
                iocs = iocs[:args.max_attrs]
            chunks = [iocs[i:i + args.chunk] for i in range(0, len(iocs), args.chunk)]
            for n, part in enumerate(chunks, 1):
                ev = {"Event": {"uuid": str(uuidlib.uuid4()), "info": meta["name"],
                                "date": time.strftime("%Y-%m-%d"), "Attribute": [
                                    {"uuid": str(uuidlib.uuid4()), "type": t, "value": v,
                                     "category": "Network activity", "to_ids": True} for t, v in part]}}
                suffix = f" (part {n}/{len(chunks)})" if len(chunks) > 1 else ""
                st, r = api.create(f"{tag} {meta['name'][:160]}{suffix}", ev,
                                   f"Imported from feed: {meta['name']} ({meta['url']})")
                if st == 201:
                    rec["cases"] += 1
                    rec["attrs_sent"] += len(part)
                else:
                    rec["errors"].append(f"part {n}: {st} {r.get('message')}"[:200])
            if not raw.strip():
                rec["skipped"] = "empty response"
            elif is_html(raw):
                rec["skipped"] = "HTML page returned instead of feed data"
            elif not iocs:
                rec["skipped"] = "no IoC parsed from content"
        rec["seconds"] = round(time.time() - rec.pop("t0"), 1)
        rec["errors"] = rec["errors"][:20]
        log.write(json.dumps(rec) + "\n")
        log.flush()
        print(json.dumps({k: rec[k] for k in ("idx", "name", "cases", "attrs_sent", "seconds")}), flush=True)


if __name__ == "__main__":
    main()
