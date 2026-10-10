"""Collects everything a report needs into a plain, serialisable structure."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select

from .. import __app_name__, __version__
from ..analyzers import all_analyzers
from ..core.timeutils import ensure_utc, to_display, utcnow
from ..storage.models import (AnalysisJob, Artifact, Case, Correlation, Device, Evidence, EvidenceFile,
                              Finding, IntegrityCheck, User)

GENERAL_LIMITATIONS = [
    "Only data present in the imported sources is reported. Absence of an artefact does not prove it never existed.",
    "Logical/backup acquisitions do not include all device data (app sandboxes, system areas, deleted space).",
    "No lock-screen bypass, exploit, encryption circumvention or remote account access was performed.",
    "Timestamps are converted to UTC using the documented method shown per record; naive times assume the case timezone.",
    "Phone number normalisation is heuristic (default country code) and must be checked against the raw value.",
    "SHA-256 hashes demonstrate that preserved bytes did not change since import; they do not alone establish "
    "authenticity or legal admissibility.",
    "Recovered/residual data (experimental module) consists of fragments with low confidence that require manual validation.",
    "Correlations of kind 'hypothesis' are analytical leads, not established facts.",
]


@dataclass
class ReportData:
    case: dict
    generated_at: datetime
    generated_by: str
    tool: str
    devices: list[dict]
    evidence: list[dict]
    methods: list[dict]
    jobs: list[dict]
    counts: dict
    tables: dict[str, list[dict]]
    timeline: list[dict]
    activity: list[tuple[str, int]]
    correlations: dict[str, list[dict]]
    findings: list[dict]
    limitations: list[str]
    audit: dict
    annex_files: list[dict]
    annex_artifacts: list[dict]
    tz: str = "UTC"
    options: dict = field(default_factory=dict)


def _art_row(a: Artifact, tz: str) -> dict:
    return {"id": a.id, "category": a.category, "subtype": a.subtype, "time": to_display(a.timestamp_utc, tz),
            "time_raw": a.timestamp_raw, "method": a.timestamp_method, "summary": a.summary, "direction": a.direction,
            "source": f"{a.source_path} [{a.source_table or '-'}#{a.source_rowid or '-'}]",
            "parser": f"{a.parser_name} {a.parser_version}", "recovered": a.is_recovered, "sha256": a.sha256,
            "lat": a.latitude, "lon": a.longitude, "location_kind": a.location_kind}


def build_report_data(ctx, s, case_id: int, username: str, max_rows: int = 200) -> ReportData:
    case = s.get(Case, case_id)
    tz = case.timezone
    owner = s.get(User, case.owner_id)
    devices = [{"label": d.label, "platform": d.platform, "manufacturer": d.manufacturer, "model": d.model,
                "os_version": d.os_version, "identifiers": d.identifiers or {}, "access_level": d.access_level,
                "limitations": d.limitations or [], "connection_state": d.connection_state,
                "authorization_ref": d.authorization_ref, "collection_scope": d.collection_scope,
                "acquired_at": to_display(d.acquired_at, tz)}
               for d in s.scalars(select(Device).where(Device.case_id == case_id))]
    evidence, annex_files, warnings = [], [], []
    for e in s.scalars(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.imported_at)):
        checks = list(s.scalars(select(IntegrityCheck).where(IntegrityCheck.evidence_id == e.id)
                                .order_by(IntegrityCheck.checked_at)))
        last = checks[-1] if checks else None
        importer = s.get(User, e.imported_by)
        evidence.append({"uid": e.uid, "name": e.original_name, "size": e.size, "sha256": e.sha256, "md5": e.md5,
                         "type": e.detected_type, "container": e.container_type, "files": e.file_count,
                         "method": e.acquisition_method, "tool": f"{e.tool_name} {e.tool_version}".strip() or "-",
                         "imported_by": importer.username if importer else "?", "imported_at": to_display(e.imported_at, tz),
                         "status": e.status, "checks": len(checks),
                         "last_check": {"at": to_display(last.checked_at, tz), "ok": last.ok, "context": last.context,
                                        "observed": last.observed} if last else None,
                         "failed_checks": sum(1 for c in checks if not c.ok)})
        warnings += [f"{e.uid}: {w}" for w in (e.warnings or [])[:20]]
        for ef in s.scalars(select(EvidenceFile).where(EvidenceFile.evidence_id == e.id).order_by(EvidenceFile.rel_path).limit(500)):
            annex_files.append({"evidence": e.uid, "path": ef.virtual_path, "size": ef.size, "sha256": ef.sha256,
                                "type": ef.detected_type})
    jobs = []
    used = Counter()
    for j in s.scalars(select(AnalysisJob).where(AnalysisJob.case_id == case_id).order_by(AnalysisJob.started_at)):
        jobs.append({"id": j.id, "status": j.status, "by": j.started_by, "started": to_display(j.started_at, tz),
                     "finished": to_display(j.finished_at, tz), "artifacts": j.artifact_count,
                     "errors": (j.errors or [])[:20]})
        for k, v in (j.analyzers or {}).items():
            if not k.startswith("_"):
                used[k] += v
    catalog = {a.name: a for a in all_analyzers()}
    methods = [{"name": n, "version": catalog[n].version if n in catalog else "1.0",
                "description": catalog[n].description if n in catalog else "Application inventory from file paths",
                "status": catalog[n].status if n in catalog else "stable", "records": c}
               for n, c in sorted(used.items())]
    counts = dict(s.execute(select(Artifact.category, func.count(Artifact.id)).where(Artifact.case_id == case_id)
                            .group_by(Artifact.category)).all())
    tables = {}
    for cat in sorted(counts):
        rows = s.scalars(select(Artifact).where(Artifact.case_id == case_id, Artifact.category == cat)
                         .order_by(Artifact.timestamp_utc.is_(None), Artifact.timestamp_utc).limit(max_rows))
        tables[cat] = [_art_row(a, tz) for a in rows]
    timeline = [_art_row(a, tz) for a in s.scalars(
        select(Artifact).where(Artifact.case_id == case_id, Artifact.timestamp_utc.is_not(None),
                               Artifact.is_recovered.is_(False), Artifact.category.in_(["message", "call", "location",
                                                                                         "media", "calendar", "browser"]))
        .order_by(Artifact.timestamp_utc).limit(max_rows * 2))]
    from ..correlation.engine import histogram
    from zoneinfo import ZoneInfo
    ts = [ensure_utc(t) for t in s.scalars(select(Artifact.timestamp_utc).where(
        Artifact.case_id == case_id, Artifact.timestamp_utc.is_not(None), Artifact.is_recovered.is_(False)))]
    activity = histogram(ts, "day", ZoneInfo(tz))
    corr = {"observed_fact": [], "hypothesis": [], "anomaly": []}
    for c in s.scalars(select(Correlation).where(Correlation.case_id == case_id).order_by(Correlation.id)):
        corr.setdefault(c.kind, []).append({"rule": c.rule, "description": c.description,
                                            "artifacts": c.artifact_ids[:30], "count": len(c.artifact_ids)})
    findings, ref_ids = [], set()
    for f in s.scalars(select(Finding).where(Finding.case_id == case_id).order_by(Finding.id)):
        findings.append({"id": f.id, "kind": f.kind, "title": f.title, "text": f.text or "", "author": f.author,
                         "created": to_display(f.created_at, tz), "artifacts": f.artifact_ids})
        ref_ids.update(f.artifact_ids)
    annex_artifacts = [_art_row(a, tz) for a in s.scalars(select(Artifact).where(Artifact.id.in_(sorted(ref_ids))))] if ref_ids else []
    limitations = list(GENERAL_LIMITATIONS)
    for d in devices:
        limitations += [f"Device '{d['label']}': {l}" for l in d["limitations"]]
    limitations += [f"Import warning - {w}" for w in warnings[:50]]
    for j in jobs:
        limitations += [f"Analysis job {j['id']}: {e}" for e in j["errors"][:10]]
    for m in methods:
        if m["status"] != "stable":
            limitations.append(f"Parser {m['name']} is '{m['status']}': results may be incomplete.")
    ok, bad_id, n = ctx.audit.verify_chain()
    return ReportData(
        case={"uid": case.uid, "title": case.title, "description": case.description or "", "status": case.status,
              "owner": owner.username if owner else "?", "legal_authority": case.legal_authority, "scope": case.scope,
              "created": to_display(case.created_at, tz), "timezone": tz},
        generated_at=utcnow(), generated_by=username, tool=f"{__app_name__} {__version__}", devices=devices,
        evidence=evidence, methods=methods, jobs=jobs, counts=counts, tables=tables, timeline=timeline,
        activity=activity, correlations=corr, findings=findings, limitations=limitations,
        audit={"chain_ok": ok, "first_broken": bad_id, "entries": n, "head_hash": ctx.audit.head_hash()},
        annex_files=annex_files, annex_artifacts=annex_artifacts, tz=tz)
