"""PDF report rendered with ReportLab (platypus)."""
from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from ..core.timeutils import to_display
from .data import ReportData

ACCENT = colors.HexColor("#1f6fd6")
DARK = colors.HexColor("#0b0d10")
GRAPHITE = colors.HexColor("#2a313a")
KIND_COLORS = {"fact": "#1d7a4c", "observed_fact": "#1d7a4c", "interpretation": "#1f5f9e",
               "hypothesis": "#a07400", "anomaly": "#b02a2a"}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("Cell", parent=ss["BodyText"], fontSize=7, leading=8.5))
    ss.add(ParagraphStyle("CellMono", parent=ss["BodyText"], fontName="Courier", fontSize=6.3, leading=7.5))
    ss.add(ParagraphStyle("H1x", parent=ss["Heading1"], textColor=ACCENT, fontSize=15, spaceBefore=10))
    ss.add(ParagraphStyle("H2x", parent=ss["Heading2"], textColor=GRAPHITE, fontSize=11.5))
    ss.add(ParagraphStyle("CoverTitle", parent=ss["Title"], fontSize=24, leading=28, textColor=DARK))
    ss.add(ParagraphStyle("Center", parent=ss["BodyText"], alignment=TA_CENTER))
    return ss


def _p(v, style):
    return Paragraph(escape("" if v is None else str(v)).replace("\n", "<br/>"), style)


def _table(rows, cols, ss, widths=None, mono=()):
    if not rows:
        return _p("No records.", ss["Italic"])
    data = [[_p(label, ss["Cell"]) for _, label in cols]]
    for r in rows:
        data.append([_p(r.get(k), ss["CellMono"] if k in mono else ss["Cell"]) for k, _ in cols])
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), GRAPHITE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9aa5b1")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f4f7")])]))
    return t


def _bar_chart(items: list[tuple[str, int]], width, height, horizontal=False):
    d = Drawing(width, height)
    chart = HorizontalBarChart() if horizontal else VerticalBarChart()
    chart.x, chart.y = 40, 20
    chart.width, chart.height = width - 60, height - 35
    chart.data = [[v for _, v in items] or [0]]
    chart.categoryAxis.categoryNames = [k for k, _ in items] or [""]
    chart.categoryAxis.labels.fontSize = 6
    if not horizontal:
        chart.categoryAxis.labels.angle = 45 if len(items) > 8 else 0
        chart.categoryAxis.labels.boxAnchor = "ne" if len(items) > 8 else "n"
    chart.valueAxis.labels.fontSize = 6
    chart.valueAxis.valueMin = 0
    chart.bars[0].fillColor = ACCENT
    d.add(chart)
    return d


def render_pdf(d: ReportData, path: Path) -> None:
    ss = _styles()
    doc = SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm, title=f"Forensic report {d.case['uid']}",
                            author=d.generated_by, creator=d.tool)
    W = landscape(A4)[0] - 24 * mm
    c = d.case
    story = []

    # --- cover
    story += [Spacer(1, 30 * mm), _p(d.tool.upper(), ss["Center"]), Spacer(1, 4 * mm),
              _p("MOBILE FORENSIC EXAMINATION REPORT", ss["Center"]), Spacer(1, 10 * mm),
              _p(c["title"], ss["CoverTitle"]), Spacer(1, 8 * mm)]
    cover = [["Case identifier", c["uid"]], ["Status", c["status"]], ["Case owner", c["owner"]],
             ["Legal authority", c["legal_authority"] or "not recorded"],
             ["Generated", f"{to_display(d.generated_at, d.tz)} by {d.generated_by}"], ["Timezone used", d.tz],
             ["Evidence sources", str(len(d.evidence))], ["Artefacts", str(sum(d.counts.values()))]]
    t = Table([[_p(a, ss["BodyText"]), _p(b, ss["BodyText"])] for a, b in cover], colWidths=[55 * mm, 150 * mm])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.grey), ("TEXTCOLOR", (0, 0), (0, -1), GRAPHITE)]))
    story += [t, PageBreak()]

    def h1(txt):
        story.append(Paragraph(escape(txt), ss["H1x"]))

    def h2(txt):
        story.append(Paragraph(escape(txt), ss["H2x"]))

    h1("1. Scope of the investigation")
    story += [_p(f"Legal authority / mandate: {c['legal_authority'] or 'not recorded'}", ss["BodyText"]),
              _p(f"Scope: {c['scope'] or 'not recorded'}", ss["BodyText"]),
              _p(f"Description: {c['description']}", ss["BodyText"])]
    h1("2. Devices")
    story.append(_table([{**dv, "ids": ", ".join(f"{k}: {v}" for k, v in dv["identifiers"].items()),
                          "lim": "; ".join(dv["limitations"])} for dv in d.devices],
                        [("label", "Label"), ("platform", "Platform"), ("model", "Model"), ("os_version", "OS"),
                         ("ids", "Identifiers"), ("access_level", "Access level"), ("authorization_ref", "Authorisation"),
                         ("acquired_at", "Acquired"), ("lim", "Limitations")], ss))
    h1("3. Methods, sources and cryptographic hashes")
    story.append(_table([{**e, "integ": ("OK" if e["last_check"] and e["last_check"]["ok"] else "ALERT") +
                          f" ({e['checks']} checks / {e['failed_checks']} failed)"} for e in d.evidence],
                        [("uid", "ID"), ("name", "Source"), ("size", "Bytes"), ("sha256", "SHA-256"), ("container", "Container"),
                         ("method", "Acquisition"), ("tool", "Tool"), ("imported_by", "By"), ("imported_at", "Imported"),
                         ("integ", "Integrity")], ss,
                        widths=[18 * mm, 35 * mm, 16 * mm, 62 * mm, 20 * mm, 26 * mm, 22 * mm, 16 * mm, 30 * mm, 28 * mm],
                        mono=("sha256",)))
    h2("Parsers applied")
    story.append(_table(d.methods, [("name", "Parser"), ("version", "Version"), ("status", "Status"),
                                    ("records", "Records"), ("description", "Description")], ss))
    h1("4. Analysis results")
    if d.counts:
        story.append(_bar_chart(sorted(d.counts.items()), W * 0.6, 130))
    for cat, rows in d.tables.items():
        cols = [("id", "#"), ("time", "Time"), ("subtype", "Type"), ("direction", "Dir."), ("summary", "Summary"),
                ("source", "Source")]
        widths = [12 * mm, 34 * mm, 22 * mm, 16 * mm, 110 * mm, 79 * mm]
        story.append(KeepTogether([Paragraph(escape(f"{cat.replace('_', ' ').title()} - {d.counts.get(cat, 0)} records "
                                                    f"(first {len(rows)} shown)"), ss["H2x"])]))
        story.append(_table(rows[:120], cols, ss, widths=widths, mono=("source",)))
    h1("5. Timeline")
    if d.activity:
        story.append(_bar_chart(d.activity[-40:], W, 150))
    story.append(_table(d.timeline[:300], [("id", "#"), ("time", "Time"), ("category", "Category"), ("direction", "Dir."),
                                           ("summary", "Summary"), ("method", "Time decoding")], ss,
                        widths=[12 * mm, 34 * mm, 20 * mm, 16 * mm, 150 * mm, 41 * mm]))
    h1("6. Correlations")
    for kind, title in (("observed_fact", "Observed facts"), ("hypothesis", "Hypotheses (analytical leads)"),
                        ("anomaly", "Temporal inconsistencies")):
        items = d.correlations.get(kind, [])
        h2(f"{title} ({len(items)})")
        story.append(_table([{**i, "refs": ", ".join(map(str, i["artifacts"]))} for i in items[:150]],
                            [("rule", "Rule"), ("description", "Description"), ("refs", "Artefact refs")], ss,
                            widths=[40 * mm, 160 * mm, 73 * mm]))
    h1("7. Examiner observations and conclusions")
    for f in d.findings:
        col = KIND_COLORS.get(f["kind"], "#333333")
        story.append(Paragraph(f'<font color="{col}"><b>[{escape(f["kind"].upper())}]</b></font> <b>{escape(f["title"])}</b>',
                               ss["BodyText"]))
        story.append(_p(f["text"], ss["BodyText"]))
        story.append(_p(f"By {f['author']} on {f['created']} - supporting artefacts: "
                        f"{', '.join('#' + str(i) for i in f['artifacts']) or 'none'}", ss["Italic"]))
        story.append(Spacer(1, 3 * mm))
    if not d.findings:
        story.append(_p("No finding recorded.", ss["Italic"]))
    h1("8. Technical limitations")
    for l in d.limitations:
        story.append(_p(f"- {l}", ss["BodyText"]))
    h1("9. Audit trail")
    a = d.audit
    story.append(_p(f"Hash-chained audit log: {'INTACT' if a['chain_ok'] else 'BROKEN at entry ' + str(a['first_broken'])} "
                    f"({a['entries']} entries). Head hash: {a['head_hash']}", ss["BodyText"]))
    story.append(PageBreak())
    h1("Annex A - Artefacts referenced by findings")
    story.append(_table(d.annex_artifacts, [("id", "#"), ("category", "Category"), ("time", "Time"), ("time_raw", "Raw"),
                                            ("method", "Decoding"), ("summary", "Summary"), ("source", "Source")], ss,
                        widths=[12 * mm, 20 * mm, 32 * mm, 28 * mm, 28 * mm, 90 * mm, 63 * mm], mono=("source",)))
    h1("Annex B - Evidence file inventory")
    story.append(_table(d.annex_files[:1500], [("evidence", "Evidence"), ("path", "Path"), ("size", "Bytes"),
                                               ("type", "Type"), ("sha256", "SHA-256")], ss,
                        widths=[22 * mm, 110 * mm, 20 * mm, 20 * mm, 101 * mm], mono=("sha256", "path")))

    def on_page(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(12 * mm, 8 * mm, f"{d.tool} - {c['uid']} - CONFIDENTIAL")
        canvas.drawRightString(landscape(A4)[0] - 12 * mm, 8 * mm, f"Page {doc_.page}")
        canvas.setStrokeColor(ACCENT)
        canvas.line(12 * mm, landscape(A4)[1] - 10 * mm, landscape(A4)[0] - 12 * mm, landscape(A4)[1] - 10 * mm)
        canvas.restoreState()

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
