# Flowintel – IoC start/end dates per threat-intelligence source

This repository holds a test install of [Flowintel](https://github.com/flowintel/flowintel) 4.0.0 (commit `8a8e8c2`, 2026-10-28) and an analysis of the start dates (`first_seen`) and end dates (`last_seen`) its IoCs carry.

For the test, all 108 sources in the MISP default feed catalogue (`feed-metadata/defaults.json`) were imported into Flowintel.

**Report:** [`report/Flowintel_TI_Source_Date_Analysis.docx`](report/Flowintel_TI_Source_Date_Analysis.docx) (Word, 23 pages), with a [PDF copy](report/Flowintel_TI_Source_Date_Analysis.pdf).

## Key results (snapshot of 29 October 2026)

| | |
|---|---|
| Sources in catalogue / usable | 108 / 79 (14 MISP format, 65 CSV/free-text) |
| IoCs imported into Flowintel | 3,521,213 in 17,045 cases |
| MISP-format IoCs with first_seen / last_seen / both | 14.9% / 16.2% / 1.1% of 1,951,282 |
| CSV/free-text IoCs with a date in Flowintel | 0 of 1,569,928 |
| Source vs Flowintel mismatches (after workaround) | 0 |
| Automated test suite | 653 of 654 passed |

- **Few sources give a full IoC lifetime.** Only the two NOCACTI feeds give both dates for every IoC. Infoblox gives only first_seen.
- **CIRCL's end dates are mostly publication days.** CIRCL OSINT's last_seen values come mostly from daily "Maltrail IOC" events.
- **Four MISP sources carry no dates at all.**
- **CSV/free-text feeds lose their dates.** Flowintel follows the MISP feed model, which keeps only the values, even when the feed lines contain dates.
- **Flowintel defects found:**
  - `misp__attribute.value` is `VARCHAR(255)`. Longer values make `POST /api/case/create_with_event` fail with HTTP 500 and leave half-imported cases. With the default schema 338,907 IoCs (9.6%) were lost.
  - First_seen/last_seen set at the MISP object level are not stored.
  - Bulk import is slow, at about 90 IoCs/s per process.

## Layout

| Path | Content |
|---|---|
| `report/` | Final report (.docx and .pdf) |
| `data/raw_stats.json` | Per-source statistics computed directly from the downloaded feed files |
| `data/flowintel_stats.json` | Per-source statistics from the Flowintel database (final, after the schema workaround) |
| `data/flowintel_stats_asis.json` | Same statistics with the default schema (before the workaround) |
| `data/summary.json` | Merged per-source view used by the report |
| `data/import_log.jsonl` | Import log per source (IoCs in source / sent, errors, skipped sources) |
| `data/repair_*.jsonl`, `data/verify_0.jsonl` | Re-creation of the cases that were incomplete because of the 255-character limit |
| `data/tests.log` | Output of the Flowintel test suite (`pytest -n 4`) |
| `data/charts/` | Charts used in the report |
| `tools/` | Download, import, statistics and repair scripts |
| `report-builder/` | Report generator (matplotlib charts, docx-js document) and run facts |

The downloaded feeds (about 1.6 GB) are not included. They change every day, and `tools/fi_fetch_feeds.py` downloads them again.

## Reproduce

Scripts that read downloaded data should be run with `python3 -I`. They need a Flowintel instance, its admin API key and, for the database scripts, `DB_NAME`, `DB_USER` and `DB_PASSWORD` set in the environment. No credentials are stored in this repository.

```sh
# 1. download all feeds of the MISP catalogue
python3 -I tools/fi_fetch_feeds.py defaults.json feeds
# 2. statistics from the raw feeds  -> raw_stats.json
python3 -I tools/fi_raw_stats.py feeds
# 3. import through the Flowintel API
python3 -I tools/fi_import_feeds.py feeds --key "$FLOWINTEL_API_KEY" --url http://127.0.0.1:7006 --log import_log.jsonl
# 4. re-create incomplete cases (after widening misp__attribute.value, see report section 4.2)
flowintel/env/bin/python -I tools/fi_repair_partial.py feeds --key "$FLOWINTEL_API_KEY" --url http://127.0.0.1:7006
# 5. statistics from the Flowintel database (read-only) -> flowintel_stats.json
flowintel/env/bin/python tools/fi_stats.py
# 6. report
cd report-builder && npm ci
python3 make_summary.py ../data out
python3 make_notes.py out/summary.json facts.json out/notes.json
node gen_report.js out report.docx
```

Test-only schema workaround, applied to the test database and not part of Flowintel:

```sql
DROP INDEX ix_misp__attribute_value;
ALTER TABLE misp__attribute ALTER COLUMN value TYPE text;
CREATE INDEX ix_misp__attribute_value ON misp__attribute USING hash (value);
CREATE INDEX ix_misp__attribute_case_misp_object_id ON misp__attribute (case_misp_object_id);
```

## Test environment

Proxmox VE 9.2 VM with 4 vCPU and 8 GB RAM, running Ubuntu 24.04.5 LTS. Flowintel ran in development launch mode (`./launch.sh -l`) with PostgreSQL 16 and Valkey 7.2. Full details are in section 3 of the report.

The IoC values summarised here come from public feeds. Each feed is subject to its provider's terms.
