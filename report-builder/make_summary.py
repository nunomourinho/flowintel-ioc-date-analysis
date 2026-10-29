#!/usr/bin/env python3
"""Merge raw_stats.json + flowintel_stats.json + import_log.jsonl into summary.json and draw charts."""
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402

BLUE, ORANGE, AQUA, GREY = "#2a78d6", "#eb6834", "#1baf7a", "#d9d8d4"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e6e5e1"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": GRID,
                     "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
                     "axes.spines.top": False, "axes.spines.right": False})


def short(name, n=40):
    return name if len(name) <= n else name[:n - 1] + "…"


def label(s):
    """Short, unambiguous source label: Fnnn + name (Rectifyq feeds differ only after 'for ')."""
    name = s["name"]
    if name.startswith("Rectifyq"):
        name = "Rectifyq " + name.split(" for ", 1)[-1].replace("Malaysian Context", "Malaysia")
    name = name.replace(" - Repackaged Öpen Source Threat Intelligence", "").replace(" Threat Intelligence", "")
    return f"F{s['idx']:03d} {short(name)}"


def main(base, out):
    raw = json.load(open(os.path.join(base, "raw_stats.json")))
    fi = json.load(open(os.path.join(base, "flowintel_stats.json")))
    imp = {}
    for l in open(os.path.join(base, "import_log.jsonl")):
        r = json.loads(l)
        imp[r["idx"]] = r
    rows = []
    for r in raw:
        i = r["idx"]
        rows.append({**{k: r[k] for k in ("idx", "name", "provider", "format", "url", "fetch")},
                     "native": r.get("native"), "native_error": r.get("native_error"),
                     "import": imp.get(i), "flowintel": fi.get(str(i))})
    summary = {"sources": rows, "baseline": fi.get("-1"), "totals": fi.get("_totals")}
    os.makedirs(out, exist_ok=True)
    json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=1)

    # Chart 1: date coverage in Flowintel per MISP-format source (share of IoCs)
    misp = [s for s in rows if s["format"] == "misp" and s["flowintel"] and s["flowintel"]["attributes"]]
    misp.sort(key=lambda s: (s["flowintel"]["both"] + s["flowintel"]["first_only"]) / s["flowintel"]["attributes"])
    fig, ax = plt.subplots(figsize=(7.2, 0.32 * len(misp) + 1.2), dpi=200)
    y = range(len(misp))
    left = [0] * len(misp)
    for key, col, lab in (("both", BLUE, "First + last seen"), ("first_only", AQUA, "First seen only"),
                          ("last_only", ORANGE, "Last seen only"), ("neither", GREY, "No dates")):
        vals = [100 * s["flowintel"][key] / s["flowintel"]["attributes"] for s in misp]
        ax.barh(list(y), vals, left=left, color=col, label=lab, height=0.62, edgecolor="white", linewidth=1)
        left = [a + b for a, b in zip(left, vals)]
    ax.set_yticks(list(y), [f"{label(s)}  (n={s['flowintel']['attributes']:,})" for s in misp])
    ax.set_xlim(0, 100)
    ax.set_xlabel("% of IoCs stored in Flowintel")
    ax.xaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.legend(ncol=4, loc="lower right", bbox_to_anchor=(1.0, 1.0), frameon=False, fontsize=7.5, handlelength=1.2)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "chart_coverage.png"))
    plt.close(fig)

    # Chart 2: IoC lifetime (last_seen - first_seen) median and P90, sources with >= 10 dated pairs
    life = [s for s in misp if s["flowintel"]["both"] >= 10 and s["flowintel"]["dur_days_median"] is not None]
    life.sort(key=lambda s: s["flowintel"]["dur_days_p90"])
    if life:
        fig, ax = plt.subplots(figsize=(7.2, 0.4 * len(life) + 1.2), dpi=200)
        for j, s in enumerate(life):
            f = s["flowintel"]
            lo, med, hi = max(f["dur_days_median"], 0.01), max(f["dur_days_median"], 0.01), max(f["dur_days_p90"], 0.01)
            ax.plot([lo, hi], [j, j], color=GRID, linewidth=2, zorder=1)
            ax.scatter([med], [j], s=40, color=BLUE, zorder=4, edgecolor="white", linewidth=1.5,
                       label="Median" if j == 0 else None)
            ax.scatter([hi], [j], s=40, color=ORANGE, zorder=3, edgecolor="white", linewidth=1.5,
                       label="90th percentile" if j == 0 else None)
        ax.set_xscale("log")
        ax.set_yticks(range(len(life)), [f"{label(s)}  (pairs={s['flowintel']['both']:,})" for s in life])
        ax.set_xlabel("IoC lifetime, last_seen − first_seen (days, log scale)")
        ax.xaxis.grid(True, color=GRID, linewidth=0.6, which="major")
        ax.set_axisbelow(True)
        ax.legend(ncol=2, loc="lower right", bbox_to_anchor=(1.0, 1.0), frameon=False, fontsize=8)
        fig.tight_layout()
        fig.savefig(os.path.join(out, "chart_lifetime.png"))
        plt.close(fig)

    # Chart 3: first_seen year distribution, all MISP sources combined
    years = {}
    for s in misp:
        for yv, n in (s["flowintel"].get("fs_years") or {}).items():
            years[int(yv)] = years.get(int(yv), 0) + n
    if years:
        ks = sorted(years)
        fig, ax = plt.subplots(figsize=(7.2, 2.6), dpi=200)
        ax.bar([str(k) for k in ks], [years[k] for k in ks], color=BLUE, width=0.7)
        ax.set_ylabel("IoCs with first_seen")
        ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v / 1000:.0f}k" if v else "0"))
        for k in ks:
            if years[k] < 1000:
                ax.annotate(f"{years[k]:,}", (str(k), years[k]), ha="center", va="bottom", fontsize=6.5, color=INK2, xytext=(0, 2), textcoords="offset points")
        ax.yaxis.grid(True, color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)
        ax.tick_params(axis="x", labelrotation=45)
        fig.tight_layout()
        fig.savefig(os.path.join(out, "chart_years.png"))
        plt.close(fig)
    print("summary + charts written to", out)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
