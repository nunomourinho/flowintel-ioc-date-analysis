#!/usr/bin/env python3
"""Download every feed listed in MISP's feed-metadata/defaults.json.

Layout: <out>/<NNN>/meta.json, raw (csv/freetext) or manifest.json + events/<uuid>.json (misp).
Writes <out>/<NNN>/fetch.json with status/sizes. Stdlib only.
"""
import argparse
import concurrent.futures as cf
import json
import os
import time
import urllib.request

UA = "Mozilla/5.0 (flowintel-test feed fetcher)"
TIMEOUT = 60


def get(url, dest=None, max_bytes=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = r.read(max_bytes + 1 if max_bytes else -1)
    if dest:
        with open(dest, "wb") as f:
            f.write(data)
    return data


def fetch_misp(base, d, max_events, max_bytes):
    base = base.rstrip("/")
    man = json.loads(get(base + "/manifest.json", os.path.join(d, "manifest.json")))
    os.makedirs(os.path.join(d, "events"), exist_ok=True)
    # Most recent first, so a cap keeps the newest events.
    uuids = sorted(man, key=lambda u: int(man[u].get("timestamp") or 0), reverse=True)
    total = len(uuids)
    if max_events:
        uuids = uuids[:max_events]
    got, err, size = 0, 0, 0

    def one(u):
        p = os.path.join(d, "events", u + ".json")
        if os.path.exists(p) and os.path.getsize(p) > 0:
            return os.path.getsize(p), None
        try:
            return len(get(f"{base}/{u}.json", p)), None
        except Exception as e:
            return 0, str(e)[:200]

    with cf.ThreadPoolExecutor(8) as ex:
        for n, e in ex.map(one, uuids):
            if e:
                err += 1
            else:
                got += 1
                size += n
            if max_bytes and size > max_bytes:
                break
    return {"events_in_manifest": total, "events_downloaded": got, "event_errors": err, "bytes": size,
            "capped": got < total}


def fetch_one(i, feed, out, args):
    F = feed["Feed"]
    d = os.path.join(out, f"{i:03d}")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "meta.json"), "w") as f:
        json.dump(F, f, indent=1)
    res = {"idx": i, "name": F["name"], "format": F["source_format"], "url": F["url"], "started": time.time()}
    try:
        if F["source_format"] == "misp":
            res.update(fetch_misp(F["url"], d, args.max_events, args.max_bytes))
        else:
            data = get(F["url"], os.path.join(d, "raw"), args.max_bytes)
            res.update({"bytes": len(data), "capped": bool(args.max_bytes and len(data) > args.max_bytes)})
        res["status"] = "ok"
    except Exception as e:
        res["status"] = "error"
        res["error"] = f"{type(e).__name__}: {e}"[:300]
    res["seconds"] = round(time.time() - res.pop("started"), 1)
    with open(os.path.join(d, "fetch.json"), "w") as f:
        json.dump(res, f, indent=1)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("defaults")
    ap.add_argument("out")
    ap.add_argument("--max-events", type=int, default=0, help="per MISP feed, 0 = all")
    ap.add_argument("--max-bytes", type=int, default=3 * 1024**3, help="per feed")
    ap.add_argument("--only", default="", help="comma list of indexes")
    args = ap.parse_args()
    feeds = json.load(open(args.defaults))
    only = {int(x) for x in args.only.split(",") if x}
    with cf.ThreadPoolExecutor(6) as ex:
        futs = [ex.submit(fetch_one, i, f, args.out, args) for i, f in enumerate(feeds) if not only or i in only]
        for fu in cf.as_completed(futs):
            r = fu.result()
            print(json.dumps(r), flush=True)


if __name__ == "__main__":
    main()
