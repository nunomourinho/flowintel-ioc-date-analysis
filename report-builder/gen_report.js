// Build the English Word report from summary.json + notes.json + charts.
// usage: node gen_report.js <dir-with-summary-notes-charts> <out.docx>
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType,
  ShadingType, AlignmentType, ImageRun, PageBreak, TableOfContents, Footer, PageNumber,
  LevelFormat, BorderStyle, Header,
} = require("docx");

const dir = process.argv[2];
const S = JSON.parse(fs.readFileSync(path.join(dir, "summary.json")));
const N = JSON.parse(fs.readFileSync(path.join(dir, "notes.json")));
const W = 9638; // A4 text width with 2 cm margins (DXA)
const FONT = "Calibri";
const HEAD_FILL = "1F3B5A", ALT_FILL = "F3F5F8";

const fmt = (n) => (n === null || n === undefined ? "–" : typeof n === "number" ? n.toLocaleString("en-GB") : String(n));
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + "%" : "–");
const day = (s) => (s ? s.slice(0, 10) : "–");
const dur = (d) => (d === null || d === undefined ? "–" : d < 1 ? d.toFixed(2) : Math.round(d).toLocaleString("en-GB"));
// Short source label; the five Rectifyq feeds differ only after "for ".
const label = (s, n = 48) => {
  let name = s.name;
  if (name.startsWith("Rectifyq")) name = "Rectifyq " + name.split(" for ").pop().replace("Malaysian Context", "Malaysia");
  name = name.replace(" - Repackaged Öpen Source Threat Intelligence", "").replace(" Threat Intelligence", "");
  return name.length > n ? name.slice(0, n - 1) + "…" : name;
};

function p(text, opts = {}) {
  const runs = Array.isArray(text) ? text : [new TextRun({ text, ...opts.run })];
  return new Paragraph({ children: runs, spacing: { after: 120, line: 276 }, ...opts.para });
}
function rich(parts) { // [["text", {bold:true}], ...]
  return new Paragraph({ spacing: { after: 120, line: 276 },
    children: parts.map(([t, o]) => new TextRun({ text: t, ...(o || {}) })) });
}
const h1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)], pageBreakBefore: true });
const h2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const h3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(t)] });
const bullet = (t, lvl = 0) => new Paragraph({ numbering: { reference: "bullets", level: lvl },
  spacing: { after: 60 }, children: Array.isArray(t) ? t.map(([x, o]) => new TextRun({ text: x, ...(o || {}) })) : [new TextRun(t)] });
const caption = (t) => new Paragraph({ alignment: AlignmentType.LEFT, spacing: { before: 60, after: 200 },
  children: [new TextRun({ text: t, italics: true, size: 18, color: "52514E" })] });

function table(headers, rows, widths, opts = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  const sz = opts.size || 16;
  const cell = (t, i, head, alt) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA },
    shading: head ? { type: ShadingType.CLEAR, fill: HEAD_FILL, color: "auto" }
      : alt ? { type: ShadingType.CLEAR, fill: ALT_FILL, color: "auto" } : undefined,
    margins: { top: 40, bottom: 40, left: 70, right: 70 },
    children: [new Paragraph({ alignment: (!head && opts.num && opts.num.includes(i)) ? AlignmentType.RIGHT : AlignmentType.LEFT,
      children: [new TextRun({ text: String(t), size: sz, bold: head, color: head ? "FFFFFF" : "1A1A1A" })] })],
  });
  return new Table({
    width: { size: total, type: WidthType.DXA }, columnWidths: widths,
    rows: [new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, i, true)) }),
      ...rows.map((r, j) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell(c, i, false, j % 2 === 1)) }))],
  });
}
function img(file, wpx) {
  const f = path.join(dir, file);
  if (!fs.existsSync(f)) return p("(chart not available)");
  const buf = fs.readFileSync(f);
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20); // PNG IHDR
  const width = wpx || 640;
  return new Paragraph({ children: [new ImageRun({ type: "png", data: buf, transformation: { width, height: Math.round(width * h / w) } })] });
}

const src = S.sources;
const misp = src.filter((s) => s.format === "misp");
const text = src.filter((s) => s.format !== "misp");
const ok = (s) => s.fetch && s.fetch.status === "ok";
const usable = (s) => ok(s) && s.flowintel && s.flowintel.attributes > 0;

// ---------- Sections ----------
const body = [];

// Title page
body.push(
  new Paragraph({ spacing: { before: 2600, after: 200 }, children: [new TextRun({ text: "Flowintel", size: 64, bold: true, color: HEAD_FILL })] }),
  new Paragraph({ spacing: { after: 200 }, children: [new TextRun({ text: "Installation test and analysis of IoC start and end dates per threat-intelligence source", size: 34, color: "333333" })] }),
  new Paragraph({ border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: HEAD_FILL, space: 4 } }, children: [] }),
  p(""),
  ...N.title_meta.map(([k, v]) => rich([[k + ": ", { bold: true }], [v]])),
  new Paragraph({ children: [new PageBreak()] }),
  new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("Contents")] }),
  new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }),
);

// 1 Executive summary
body.push(h1("1. Executive summary"));
N.summary.forEach((t) => body.push(p(t)));
body.push(h3("Key figures"));
body.push(table(["Measure", "Value"], N.key_figures, [6200, 3438], { num: [1], size: 18 }));
body.push(h3("Main findings"));
N.findings_short.forEach((t) => body.push(bullet(t)));

// 2 Scope and approach
body.push(h1("2. Scope and approach"));
N.scope.forEach((t) => body.push(p(t)));
body.push(h2("2.1 Definitions"));
N.definitions.forEach(([k, v]) => body.push(bullet([[k + " – ", { bold: true }], [v]])));

// 3 Test environment
body.push(h1("3. Test environment"));
body.push(table(["Component", "Value"], N.environment, [3000, 6638], { size: 18 }));

// 4 Installation
body.push(h1("4. Installation of Flowintel"));
N.install_intro.forEach((t) => body.push(p(t)));
body.push(h2("4.1 Steps performed"));
N.install_steps.forEach(([t, cmd]) => { body.push(bullet(t)); if (cmd) body.push(new Paragraph({ indent: { left: 720 }, spacing: { after: 80 }, children: [new TextRun({ text: cmd, font: "Consolas", size: 16, color: "333333" })] })); });
body.push(h2("4.2 Issues and deviations found"));
body.push(table(["#", "Observation", "Impact / action taken"], N.install_issues.map((r, i) => [i + 1, r[0], r[1]]), [500, 4400, 4738], { size: 16 }));
body.push(h2("4.3 Functional verification"));
body.push(table(["Check", "Result"], N.functional, [4200, 5438], { size: 16 }));

// 5 Sources
body.push(h1("5. Threat-intelligence sources"));
N.sources_intro.forEach((t) => body.push(p(t)));
const byFmt = {};
src.forEach((s) => { const k = s.format; byFmt[k] = byFmt[k] || { total: 0, ok: 0, imp: 0, iocs: 0 }; byFmt[k].total++; if (ok(s)) byFmt[k].ok++; if (usable(s)) { byFmt[k].imp++; byFmt[k].iocs += s.flowintel.attributes; } });
body.push(table(["Feed format", "Listed", "Downloaded", "Imported into Flowintel", "IoCs imported"],
  Object.entries(byFmt).map(([k, v]) => [k, v.total, v.ok, v.imp, fmt(v.iocs)]).concat([["Total", src.length,
    src.filter(ok).length, src.filter(usable).length, fmt(src.filter(usable).reduce((a, s) => a + s.flowintel.attributes, 0))]]),
  [2200, 1500, 1700, 2300, 1938], { num: [1, 2, 3, 4], size: 18 }));
body.push(caption("Table 5.1 – Source catalogue: MISP project default feed list (feed-metadata/defaults.json), all 108 entries."));
body.push(h2("5.1 Sources that could not be used"));
body.push(p(N.unavailable_intro));
const bad = src.filter((s) => !usable(s));
body.push(table(["ID", "Source", "Format", "Reason"], bad.map((s) => [
  "F" + String(s.idx).padStart(3, "0"), s.name.slice(0, 70), s.format,
  !ok(s) ? (s.fetch.error || "download failed") : (s.import && s.import.skipped) || "not imported"]),
  [700, 4300, 900, 3738], { size: 15 }));

// 6 Results MISP-format
body.push(h1("6. Results – MISP-format sources (IoCs with native dates)"));
N.misp_intro.forEach((t) => body.push(p(t)));
const mispOk = misp.filter((s) => s.flowintel && s.flowintel.attributes);
body.push(h2("6.1 Start and end dates per source"));
body.push(table(["ID", "Source", "Events", "IoCs", "first_seen", "last_seen", "Both", "None", "% with any date"],
  mispOk.map((s) => { const f = s.flowintel; return ["F" + String(s.idx).padStart(3, "0"), label(s, 48), fmt(f.cases), fmt(f.attributes),
    fmt(f.first_seen), fmt(f.last_seen), fmt(f.both), fmt(f.neither), pct(f.attributes - f.neither, f.attributes)]; }),
  [600, 2700, 750, 1000, 950, 950, 900, 900, 888], { num: [2, 3, 4, 5, 6, 7, 8], size: 15 }));
body.push(caption("Table 6.1 – IoCs (MISP attributes, standalone and inside objects) stored by Flowintel per source, and how many carry first_seen / last_seen."));
body.push(img("chart_coverage.png", 640));
body.push(caption("Figure 6.1 – Share of IoCs per source with start date, end date, both, or neither (as stored in Flowintel)."));

body.push(h2("6.2 Date ranges and IoC lifetime"));
body.push(p(N.lifetime_intro));
const dated = mispOk.filter((s) => s.flowintel.first_seen || s.flowintel.last_seen);
body.push(table(["ID", "Source", "first_seen range", "last_seen range", "Median (d)", "P90 (d)", "Max (d)", "Zero-length", "Inverted"],
  dated.map((s) => { const f = s.flowintel; return ["F" + String(s.idx).padStart(3, "0"), label(s, 40),
    f.first_seen ? `${day(f.fs_min)} → ${day(f.fs_max)}` : "–", f.last_seen ? `${day(f.ls_min)} → ${day(f.ls_max)}` : "–",
    dur(f.dur_days_median), dur(f.dur_days_p90), dur(f.dur_days_max), fmt(f.both ? f.dur_zero : null), fmt(f.both ? f.inverted : null)]; }),
  [600, 2050, 1500, 1500, 800, 800, 800, 800, 788], { num: [4, 5, 6, 7, 8], size: 15 }));
body.push(caption("Table 6.2 – Range of the dates found and lifetime statistics (last_seen − first_seen, in days) for IoCs that have both dates."));
body.push(img("chart_lifetime.png", 640));
body.push(caption("Figure 6.2 – Median and 90th percentile of IoC lifetime per source (sources with at least 10 IoCs having both dates)."));
body.push(img("chart_years.png", 640));
body.push(caption("Figure 6.3 – Year of first_seen, all MISP-format sources combined."));

body.push(h2("6.3 Other information available per source"));
body.push(p(N.info_intro));
body.push(table(["ID", "Source", "Objects", "Main IoC types", "IDS flag", "Object-level dates (source)", "first/last-seen as object attributes (source)"],
  mispOk.map((s) => { const n = s.native || {}, f = s.flowintel; return ["F" + String(s.idx).padStart(3, "0"), label(s, 34), fmt(n.objects),
    (f.types_top || []).slice(0, 3).map(([t, c]) => `${t} ${pct(c, f.attributes)}`).join(", "), pct(f.ids_flag, f.attributes),
    `${fmt(n.obj_first_seen)} / ${fmt(n.obj_last_seen)}`, `${fmt(n.rel_first_seen)} / ${fmt(n.rel_last_seen)}`]; }),
  [600, 1900, 800, 2700, 800, 1400, 1438], { num: [2, 4], size: 15 }));
body.push(caption("Table 6.3 – Structure of each MISP-format source. Object-level first_seen/last_seen and first-seen/last-seen object attributes are counted in the raw feed."));

body.push(h2("6.4 Integrity check: source vs Flowintel"));
body.push(p(N.integrity_intro));
body.push(table(["ID", "Source", "IoCs in source", "IoCs in Flowintel", "first_seen source / Flowintel", "last_seen source / Flowintel", "Match"],
  mispOk.map((s) => { const n = s.native || {}, f = s.flowintel; const m = n.attributes === f.attributes && n.first_seen === f.first_seen && n.last_seen === f.last_seen;
    return ["F" + String(s.idx).padStart(3, "0"), label(s, 38), fmt(n.attributes), fmt(f.attributes), `${fmt(n.first_seen)} / ${fmt(f.first_seen)}`, `${fmt(n.last_seen)} / ${fmt(f.last_seen)}`, m ? "Yes" : "No"]; }),
  [600, 2400, 1250, 1250, 1600, 1600, 938], { num: [2, 3], size: 15 }));
body.push(caption("Table 6.4 – Counts computed directly from the downloaded feed files compared with what Flowintel stored."));
(N.integrity_notes || []).forEach((t) => body.push(bullet(t)));

// 7 CSV / freetext
body.push(h1("7. Results – CSV and free-text sources"));
N.text_intro.forEach((t) => body.push(p(t)));
const textOk = text.filter(usable);
body.push(table(["ID", "Source", "Fmt", "Rows", "IoCs in Flowintel", "Main type", "Rows with 1 date", "Rows with ≥2 dates", "Dates in Flowintel"],
  textOk.map((s) => { const n = s.native || {}, f = s.flowintel || {}; return ["F" + String(s.idx).padStart(3, "0"), s.name.slice(0, 40), s.format === "freetext" ? "text" : "csv",
    fmt(n.data_rows), fmt(f.attributes), (f.types_top || [[""]])[0][0], fmt(n.rows_1_date), fmt(n.rows_2plus_dates), fmt((f.first_seen || 0) + (f.last_seen || 0))]; }),
  [600, 2700, 550, 950, 1050, 1000, 900, 950, 938], { num: [3, 4, 6, 7, 8], size: 15 }));
body.push(caption("Table 7.1 – CSV/free-text sources: rows in the feed, IoCs stored in Flowintel, and rows whose raw line contains one or more date values."));
(N.text_notes || []).forEach((t) => body.push(bullet(t)));

// 8 Findings
body.push(h1("8. Findings and recommendations"));
N.findings.forEach(([t, d]) => { body.push(h3(t)); d.forEach((x) => body.push(p(x))); });
body.push(h2("Recommendations"));
N.recommendations.forEach((t) => body.push(bullet(t)));

// 9 Limitations
body.push(h1("9. Limitations"));
N.limitations.forEach((t) => body.push(bullet(t)));

// Appendix
body.push(h1("Appendix A – Full source list"));
body.push(table(["ID", "Source", "Provider", "Format", "Status", "IoCs imported"],
  src.map((s) => ["F" + String(s.idx).padStart(3, "0"), s.name.slice(0, 60), (s.provider || "").slice(0, 30), s.format,
    usable(s) ? "Imported" : ok(s) ? "Downloaded, not usable" : "Unavailable", usable(s) ? fmt(s.flowintel.attributes) : "–"]),
  [600, 3700, 2000, 800, 1500, 1038], { num: [5], size: 14 }));
body.push(h1("Appendix B – Commands and scripts"));
N.appendix_b.forEach(([t, c]) => { body.push(p(t, { run: { bold: true } })); c.split("\n").forEach((l) => body.push(new Paragraph({ spacing: { after: 0 }, indent: { left: 360 }, children: [new TextRun({ text: l, font: "Consolas", size: 16 })] }))); body.push(p("")); });

const doc = new Document({
  creator: N.creator, title: "Flowintel – TI source date analysis",
  styles: {
    default: { document: { run: { font: FONT, size: 21 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 32, bold: true, color: HEAD_FILL, font: FONT }, paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 26, bold: true, color: "2A5A8A", font: FONT }, paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 22, bold: true, color: "333333", font: FONT }, paragraph: { spacing: { before: 180, after: 80 }, outlineLevel: 2 } },
    ],
  },
  numbering: { config: [{ reference: "bullets", levels: [
    { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } },
    { level: 1, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1080, hanging: 270 } } } }] }] },
  features: { updateFields: true },
  sections: [{
    properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
    headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "Flowintel – TI source date analysis", size: 16, color: "888888" })] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: ["Page ", PageNumber.CURRENT, " of ", PageNumber.TOTAL_PAGES], size: 16, color: "888888" })] })] }) },
    children: body,
  }],
});
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(process.argv[3], b); console.log("written", process.argv[3]); });
