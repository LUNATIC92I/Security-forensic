"""Self-contained HTML report (no external resources, all values escaped)."""
from __future__ import annotations

from html import escape

from ..core.timeutils import to_display
from .data import ReportData

CSS = """
:root{--bg:#0b0d10;--panel:#14181d;--line:#2a313a;--text:#d7dde4;--muted:#8b96a3;--accent:#2f8cff;--ok:#2bb673;--bad:#ff4d4f;--warn:#f5a623}
body{background:var(--bg);color:var(--text);font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:0 24px 48px;line-height:1.45}
@media print{body{background:#fff;color:#000}.panel{border-color:#999}}
h1{font-size:28px;margin:0}h2{border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:36px;color:var(--accent)}
h3{margin-top:22px}.cover{padding:48px 0 24px;border-bottom:2px solid var(--accent)}
.muted{color:var(--muted)}.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px 16px;margin:10px 0}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin:8px 0}th,td{border:1px solid var(--line);padding:4px 6px;vertical-align:top;text-align:left}
th{background:#1b2027}td.mono,.mono{font-family:Consolas,Menlo,monospace;font-size:11.5px;word-break:break-all}
.tag{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;font-weight:600}
.fact,.observed_fact{background:#123d29;color:#7ff0b4}.interpretation{background:#16314f;color:#9fcbff}.hypothesis{background:#4a3a12;color:#ffd47f}
.anomaly{background:#4a1616;color:#ff9c9c}.ok{color:var(--ok)}.bad{color:var(--bad)}
.bar{display:inline-block;background:var(--accent);height:10px;vertical-align:middle}
"""


def _e(v) -> str:
    return escape("" if v is None else str(v))


def _table(rows: list[dict], cols: list[tuple[str, str]], mono: set[str] = frozenset()) -> str:
    if not rows:
        return '<p class="muted">No records.</p>'
    head = "".join(f"<th>{_e(label)}</th>" for _, label in cols)
    body = "".join("<tr>" + "".join(f'<td class="{"mono" if k in mono else ""}">{_e(r.get(k))}</td>' for k, _ in cols) + "</tr>"
                   for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(d: ReportData) -> str:
    c = d.case
    p = []
    p.append(f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forensic report {_e(c['uid'])}</title><style>{CSS}</style></head><body>""")
    p.append(f"""<div class="cover"><div class="muted">{_e(d.tool)} - Mobile forensic examination report</div>
<h1>{_e(c['title'])}</h1><p>Case identifier: <b class="mono">{_e(c['uid'])}</b> &middot; Status: {_e(c['status'])}</p>
<p class="muted">Generated {_e(to_display(d.generated_at, d.tz))} by {_e(d.generated_by)} &middot; Case owner {_e(c['owner'])} &middot; Times shown in {_e(d.tz)}</p></div>""")
    p.append("<h2>1. Scope of the investigation</h2>")
    p.append(f'<div class="panel"><p><b>Legal authority / mandate:</b> {_e(c["legal_authority"]) or "<i>not recorded</i>"}</p>'
             f'<p><b>Scope:</b> {_e(c["scope"]) or "<i>not recorded</i>"}</p><p><b>Description:</b> {_e(c["description"])}</p></div>')
    p.append("<h2>2. Devices</h2>")
    for dv in d.devices:
        ids = ", ".join(f"{k}: {v}" for k, v in dv["identifiers"].items())
        p.append(f'<div class="panel"><b>{_e(dv["label"])}</b> - {_e(dv["platform"])} {_e(dv["manufacturer"])} {_e(dv["model"])} '
                 f'(OS {_e(dv["os_version"])})<br>Identifiers: <span class="mono">{_e(ids) or "-"}</span><br>'
                 f'Access level: {_e(dv["access_level"])} &middot; Connection: {_e(dv["connection_state"])} &middot; Acquired: {_e(dv["acquired_at"])}<br>'
                 f'Authorisation: {_e(dv["authorization_ref"]) or "-"} &middot; Collection scope: {_e(dv["collection_scope"]) or "-"}<br>'
                 f'Limitations: {_e("; ".join(dv["limitations"])) or "-"}</div>')
    if not d.devices:
        p.append('<p class="muted">No device record.</p>')
    p.append("<h2>3. Methods, sources and tools</h2>")
    p.append("<h3>Evidence sources and cryptographic hashes</h3>")
    ev_rows = [{**e, "integrity": ("OK" if e["last_check"] and e["last_check"]["ok"] else "ALERT") +
                f" ({e['checks']} checks, {e['failed_checks']} failed)"} for e in d.evidence]
    p.append(_table(ev_rows, [("uid", "ID"), ("name", "Source"), ("size", "Bytes"), ("sha256", "SHA-256"), ("md5", "MD5"),
                              ("container", "Container"), ("files", "Files"), ("method", "Acquisition"), ("tool", "Tool"),
                              ("imported_by", "Imported by"), ("imported_at", "Imported at"), ("integrity", "Integrity")],
                    {"sha256", "md5"}))
    p.append("<h3>Parsers applied</h3>")
    p.append(_table(d.methods, [("name", "Parser"), ("version", "Version"), ("status", "Status"), ("records", "Records"),
                                ("description", "Description")]))
    p.append("<h3>Analysis jobs</h3>")
    p.append(_table(d.jobs, [("id", "Job"), ("status", "Status"), ("by", "By"), ("started", "Started"),
                             ("finished", "Finished"), ("artifacts", "Artefacts")]))
    p.append("<h2>4. Analysis results</h2>")
    total = sum(d.counts.values()) or 1
    p.append("<table><tr><th>Category</th><th>Records</th><th></th></tr>" + "".join(
        f'<tr><td>{_e(k)}</td><td>{v}</td><td><span class="bar" style="width:{int(300 * v / total)}px"></span></td></tr>'
        for k, v in sorted(d.counts.items())) + "</table>")
    for cat, rows in d.tables.items():
        p.append(f"<h3>{_e(cat.replace('_', ' ').title())} ({d.counts.get(cat, 0)} records, first {len(rows)} shown)</h3>")
        cols = [("id", "#"), ("time", "Time"), ("subtype", "Type"), ("direction", "Dir."), ("summary", "Summary"), ("source", "Source")]
        if cat in ("media", "document", "recovered"):
            cols.insert(5, ("sha256", "SHA-256"))
        if cat in ("location", "media"):
            cols.insert(5, ("location_kind", "Loc. kind"))
        p.append(_table(rows, cols, {"sha256", "source"}))
    p.append("<h2>5. Timeline</h2>")
    if d.activity:
        mx = max(v for _, v in d.activity) or 1
        p.append("<h3>Activity per day</h3><table><tr><th>Day</th><th>Events</th><th></th></tr>" + "".join(
            f'<tr><td>{_e(k)}</td><td>{v}</td><td><span class="bar" style="width:{int(300 * v / mx)}px"></span></td></tr>'
            for k, v in d.activity[-120:]) + "</table>")
    p.append(_table(d.timeline, [("id", "#"), ("time", "Time"), ("category", "Category"), ("direction", "Dir."),
                                 ("summary", "Summary"), ("method", "Time decoding"), ("source", "Source")], {"source"}))
    p.append("<h2>6. Correlations</h2>")
    for kind, title in (("observed_fact", "Observed facts"), ("hypothesis", "Hypotheses (analytical leads)"),
                        ("anomaly", "Temporal inconsistencies")):
        items = d.correlations.get(kind, [])
        p.append(f'<h3><span class="tag {kind}">{_e(kind)}</span> {title} ({len(items)})</h3>')
        p.append(_table([{**i, "artifacts": ", ".join(map(str, i["artifacts"])) + (" ..." if i["count"] > 30 else "")}
                         for i in items[:200]], [("rule", "Rule"), ("description", "Description"), ("artifacts", "Artefact refs")]))
    p.append("<h2>7. Examiner observations and conclusions</h2>")
    for f in d.findings:
        p.append(f'<div class="panel"><span class="tag {f["kind"]}">{_e(f["kind"])}</span> <b>{_e(f["title"])}</b>'
                 f'<p>{_e(f["text"])}</p><p class="muted">By {_e(f["author"])} on {_e(f["created"])} - supporting artefacts: '
                 f'{_e(", ".join("#" + str(i) for i in f["artifacts"])) or "none"}</p></div>')
    if not d.findings:
        p.append('<p class="muted">No finding recorded.</p>')
    p.append("<h2>8. Technical limitations</h2><ul>" + "".join(f"<li>{_e(l)}</li>" for l in d.limitations) + "</ul>")
    p.append("<h2>9. Audit trail</h2>")
    a = d.audit
    p.append(f'<div class="panel">Hash-chained audit log: <b class="{"ok" if a["chain_ok"] else "bad"}">'
             f'{"INTACT" if a["chain_ok"] else "BROKEN at entry " + _e(a["first_broken"])}</b> ({a["entries"]} entries)<br>'
             f'Head hash: <span class="mono">{_e(a["head_hash"])}</span></div>')
    p.append("<h2>Annex A - Artefacts referenced by findings</h2>")
    p.append(_table(d.annex_artifacts, [("id", "#"), ("category", "Category"), ("time", "Time"), ("time_raw", "Raw time"),
                                        ("method", "Decoding"), ("summary", "Summary"), ("source", "Source"), ("parser", "Parser")],
                    {"source"}))
    p.append("<h2>Annex B - Evidence file inventory (first 500 per source)</h2>")
    p.append(_table(d.annex_files, [("evidence", "Evidence"), ("path", "Path"), ("size", "Bytes"), ("type", "Type"),
                                    ("sha256", "SHA-256")], {"sha256", "path"}))
    p.append(f'<p class="muted">End of report - {_e(d.tool)}</p></body></html>')
    return "\n".join(p)
