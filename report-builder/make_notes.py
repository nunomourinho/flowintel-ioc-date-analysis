#!/usr/bin/env python3
"""Write notes.json (narrative + key tables for gen_report.js) from summary.json and run facts."""
import json
import sys

S = json.load(open(sys.argv[1]))
facts = json.load(open(sys.argv[2]))  # run facts gathered on the VM (versions, impact, tests)
src = S["sources"]
use = [s for s in src if s["fetch"]["status"] == "ok" and s["flowintel"] and s["flowintel"]["attributes"]]
misp = [s for s in use if s["format"] == "misp"]
text = [s for s in use if s["format"] != "misp"]
tot = lambda L, k: sum(s["flowintel"][k] for s in L)
n_all = tot(use, "attributes")
n_m = tot(misp, "attributes")
fs, ls, both, neither = tot(misp, "first_seen"), tot(misp, "last_seen"), tot(misp, "both"), tot(misp, "neither")
any_date = n_m - neither
full = [s for s in misp if s["flowintel"]["both"] == s["flowintel"]["attributes"]]
nodate = [s for s in misp if s["flowintel"]["neither"] == s["flowintel"]["attributes"]]
f = lambda n: f"{n:,}"
p = lambda a, b: f"{100 * a / b:.1f}%"
name = lambda i: next(s["name"] for s in src if s["idx"] == i)
T = facts["tests"]
dated_text = [s for s in text if s["native"] and s["native"].get("data_rows")
              and (s["native"]["rows_1_date"] + s["native"]["rows_2plus_dates"]) >= 0.5 * s["native"]["data_rows"]]

notes = {
    "creator": "Claude Code",
    "title_meta": [
        ["Software", f"Flowintel {facts['fi_version']} (commit {facts['fi_commit']})"],
        ["Test platform", "Proxmox VE 9.2 – VM 106 'flowintel-test', Ubuntu 24.04.5 LTS"],
        ["Sources evaluated", f"{len(src)} threat-intelligence feeds (MISP default feed catalogue)"],
        ["Date", "29 October 2026"],
        ["Prepared with", "Claude Code"],
    ],
    "summary": [
        f"Flowintel {facts['fi_version']} was installed from the official repository on a new Ubuntu 24.04 virtual machine on the Proxmox host, using the project's install.sh with PostgreSQL 16 and Valkey 7.2. The web application, the REST API, the MISP modules and the bundled test data all worked. {T['summary_sentence']}",
        f"Flowintel does not collect threat intelligence itself; IoCs enter it as MISP events. All {len(src)} sources in the MISP project's default feed catalogue were therefore downloaded and imported through the Flowintel API (POST /api/case/create_with_event). {len(use)} sources could be used ({len(misp)} in MISP format, {len(text)} CSV/free-text); {len(src) - len(use)} were unavailable or returned no data. In total {f(n_all)} IoCs were stored in {f(S['totals']['cases'])} cases.",
        f"For every source the start date (first_seen) and end date (last_seen) of each IoC were counted, statistically described and compared with the raw feed. Only MISP-format sources carry IoC dates: of {f(n_m)} IoCs, {f(fs)} ({p(fs, n_m)}) have a start date, {f(ls)} ({p(ls, n_m)}) an end date and {f(both)} ({p(both, n_m)}) both. {len(nodate)} of the {len(misp)} MISP sources provide no IoC dates at all, and none of the {f(tot(text, 'attributes'))} CSV/free-text IoCs has a date in Flowintel, even where the feed lines contain dates.",
        f"Flowintel preserves attribute dates exactly (0 differences between source and Flowintel after the workaround described below). Two defects affect the result, however: (1) IoC values longer than 255 characters make the import fail with HTTP 500 and leave incomplete cases, which in the default configuration lost {f(facts['asis_missing'])} IoCs ({p(facts['asis_missing'], n_all)}) from 15 sources; (2) first_seen/last_seen set at MISP-object level are not stored by Flowintel.",
    ],
    "key_figures": [
        ["Sources in catalogue / usable", f"{len(src)} / {len(use)}"],
        ["IoCs imported into Flowintel", f(n_all)],
        ["Cases created", f(S["totals"]["cases"])],
        ["IoCs from MISP-format sources", f(n_m)],
        ["… with first_seen (start date)", f"{f(fs)} ({p(fs, n_m)})"],
        ["… with last_seen (end date)", f"{f(ls)} ({p(ls, n_m)})"],
        ["… with both dates", f"{f(both)} ({p(both, n_m)})"],
        ["… with no date", f"{f(neither)} ({p(neither, n_m)})"],
        ["IoCs from CSV/free-text sources (no dates in Flowintel)", f(tot(text, "attributes"))],
        ["Source vs Flowintel mismatches (after workaround)", "0"],
        ["IoCs lost with default schema (value > 255 chars)", f"{f(facts['asis_missing'])} ({p(facts['asis_missing'], n_all)})"],
        ["Automated test suite", T["key"]],
    ],
    "findings_short": [
        f"Only {len(full)} sources ({', '.join(name(s['idx']) for s in full)}) give both dates for every IoC; Infoblox gives a start date for all {f(269362)} IoCs but never an end date.",
        f"CIRCL OSINT, the largest source ({f(588220)} IoCs), has an end date on 51% of IoCs, almost all from the daily 'Maltrail IOC' events where last_seen is the publication day, and both dates on only 1.1%.",
        f"Rösti, PrecisionSec, TweetFeed and SiberKapan ({f(428536 + 90353 + 97979 + 14427)} IoCs) carry no IoC dates; PrecisionSec puts dates in first-seen/last-seen object attributes instead ({f(14835)} / {f(4792)}).",
        f"CSV/free-text feeds never yield dates in Flowintel (as in MISP), although {len(dated_text)} of them have dates on most lines (e.g. dataplane.org, abuse.ch SSLBL, Phishtank).",
        "Flowintel bug: misp__attribute.value is VARCHAR(255); longer values abort the request with HTTP 500 and the case is left half-imported because each attribute is committed separately.",
        "Flowintel does not store object-level first_seen/last_seen (e.g. all 1,801 dated objects of NOCACTI Intrusion, 859 of Rectifyq 2026).",
    ],
    "scope": [
        "The task had three parts: (1) install a new Ubuntu VM on Proxmox; (2) install and test Flowintel on it; (3) import all threat-intelligence sources containing IoCs and evaluate, for each source, the information available and how many IoCs have a start date and an end date, with statistics.",
        "Source catalogue. Flowintel has no feed catalogue of its own; its threat-intelligence model is MISP. The authoritative public list of MISP feeds, feed-metadata/defaults.json from the MISP project (108 feeds), was used as the definition of 'all sources'.",
        "Import path. MISP-format feeds were downloaded in full (manifest.json plus every event) and each event was sent unchanged to POST /api/case/create_with_event, one case per event. CSV and free-text feeds were parsed with the value columns and exclusion rules defined for each feed in the catalogue, the same way MISP does it, and sent as one event per feed (split into cases of at most 50,000 IoCs). MISP does not map dates from CSV/free-text feeds either, so these IoCs carry no first_seen/last_seen.",
        "Measurement. Statistics were computed twice: directly from the downloaded feed files (the 'source' view) and from the Flowintel PostgreSQL database through a read-only query (the 'Flowintel' view). The two views were compared source by source.",
    ],
    "definitions": [
        ["IoC", "A MISP attribute stored by Flowintel (table misp__attribute), standalone or inside a MISP object."],
        ["Start date", "Attribute first_seen."],
        ["End date", "Attribute last_seen."],
        ["Both / none", "IoC with first_seen and last_seen / with neither."],
        ["Lifetime", "last_seen − first_seen in days, for IoCs that have both; median, mean, 90th percentile and maximum are reported."],
        ["Inverted", "IoC whose last_seen is earlier than its first_seen (none were found)."],
        ["Zero-length", "IoC whose first_seen equals last_seen."],
    ],
    "environment": facts["environment"],
    "install_intro": [
        "Installation followed the README quick start. The only choices made were PostgreSQL as database (README prerequisite) and binding the development server to all interfaces so the UI is reachable from the host network. Configuration is supplied as environment variables (the application reads no .env file).",
    ],
    "install_steps": facts["install_steps"],
    "install_issues": facts["install_issues"],
    "functional": facts["functional"],
    "sources_intro": [
        f"The catalogue contains {len(src)} feeds: 18 MISP-format, 47 CSV and 43 free-text. Downloads were made from the VM on 29 October 2026 with up to two retries; TweetFeed needed a slow sequential retry because of rate limiting.",
    ],
    "unavailable_intro": "The following sources could not be used. Most are discontinued or moved (abuse.ch returns 410 Gone for all legacy export URLs), require registration, or returned an HTML page or empty content.",
    "misp_intro": [
        "MISP-format sources are the only ones whose IoCs can carry start and end dates. Table 6.1 gives the counts per source as stored in Flowintel; they are identical to the counts computed from the raw feed files (section 6.4).",
    ],
    "lifetime_intro": "For IoCs that have both dates, the interval last_seen − first_seen was computed. No inverted ranges were found in any source. Several sources mainly give zero- or near-zero-length intervals (first and last observation within minutes), so the dates describe a single sighting rather than an active period.",
    "info_intro": "Besides attribute dates, sources differ in structure. Several put date information where Flowintel does not keep it: in object-level first_seen/last_seen (dropped by Flowintel) or in date-typed object attributes such as first-seen/last-seen (kept as plain attribute values, not as IoC dates).",
    "integrity_intro": "Each MISP-format source was checked by comparing the number of IoCs, first_seen and last_seen computed from the downloaded files with the values in Flowintel. After the schema workaround (section 4.2) all sources match exactly. CSV/free-text sources were checked by comparing the number of parsed IoCs with the number stored (all match).",
    "integrity_notes": [
        f"With the default schema the same comparison fails for 15 sources: {f(facts['asis_missing'])} IoCs were missing, including {f(6419 - 4568)} dated IoCs of NOCACTI Intrusion and {f(7118 - 2474)} of Rectifyq 2026.",
        f"Values over 255 characters: {f(facts['long_values'])} (longest {f(facts['max_len'])} characters) – mostly URLs, YARA/Sigma rule text and long descriptions.",
    ],
    "text_intro": [
        f"{len(text)} CSV/free-text sources were imported ({f(tot(text, 'attributes'))} IoCs, mainly IP addresses, domains and URLs). None of these IoCs has a first_seen or last_seen in Flowintel. The table also shows how many feed lines contain one or more dates, i.e. date information that the source has but that the standard MISP/Flowintel import does not use.",
    ],
    "text_notes": [
        "dataplane.org feeds (12 sources) have one timestamp per line (last observation); Feodo, ipspamlist and the MalSilo feeds have explicit first-seen / last-seen columns; Phishtank has submission and verification times.",
        "Using these dates would need a custom parser that maps the columns to first_seen/last_seen; it is not part of MISP feed handling or of Flowintel.",
        "James Brine (89,421 lines, 12,608 unique IPs) and the APNIC honeypot feeds contain repeated IoCs; duplicates within a source were removed.",
    ],
    "findings": facts["findings"],
    "recommendations": facts["recommendations"],
    "limitations": facts["limitations"],
    "appendix_b": facts["appendix_b"],
}
json.dump(notes, open(sys.argv[3], "w"), indent=1, ensure_ascii=False)
print("notes written")
