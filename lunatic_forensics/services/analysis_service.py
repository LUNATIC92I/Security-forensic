"""Runs analyzers over the working copies of an evidence item and stores artefacts."""
from __future__ import annotations

import logging
import traceback
from collections import Counter
from pathlib import Path

from sqlalchemy import delete, func, select

from .. import __version__
from ..analyzers import all_analyzers
from ..analyzers.apps import inventory_apps
from ..analyzers.base import ArtifactRecord, FileContext
from ..core.errors import IntegrityViolation, NotFound, persist
from ..core.normalize import pack_identifiers
from ..core.rbac import Perm
from ..core.timeutils import utcnow
from ..storage.models import AnalysisJob, Artifact, Case, Correlation, Evidence, EvidenceFile, Finding
from .base import ServiceBase

log = logging.getLogger("lunatic.analysis")
BATCH = 500


def record_to_artifact(rec: ArtifactRecord, *, case_id, evidence_id, evidence_file_id, job_id, source_path,
                       parser_name, parser_version) -> Artifact:
    return Artifact(
        case_id=case_id, evidence_id=evidence_id, evidence_file_id=evidence_file_id, job_id=job_id,
        category=rec.category.value, subtype=rec.subtype[:60], timestamp_utc=rec.timestamp,
        timestamp_raw=(rec.timestamp_raw or None) and str(rec.timestamp_raw)[:100],
        timestamp_method=rec.timestamp_method, summary=(rec.summary or "")[:500],
        identifiers=pack_identifiers(rec.identifiers), names="|".join(n for n in rec.names if n)[:2000],
        conversation_id=rec.conversation_id[:300] if rec.conversation_id else None, direction=rec.direction,
        latitude=rec.latitude, longitude=rec.longitude, location_kind=rec.location_kind, sha256=rec.sha256,
        mime=rec.mime, source_path=source_path, source_table=rec.source_table, source_rowid=rec.source_rowid,
        parser_name=parser_name, parser_version=parser_version, is_recovered=rec.is_recovered,
        confidence=rec.confidence, content_hash=rec.content_hash(),
        data={"raw": rec.raw, "interpreted": rec.interpreted})


class AnalysisService(ServiceBase):
    def analyzers_catalog(self) -> list[dict]:
        return [{"name": a.name, "version": a.version, "categories": [c.value for c in a.categories],
                 "description": a.description, "sources": a.sources, "status": a.status,
                 "fallback": a.fallback} for a in all_analyzers()]

    def run(self, actor, evidence_id: int, only: list[str] | None = None, progress=None,
            correlate: bool = True) -> int:
        self.authorize(actor, Perm.RUN_ANALYSIS)
        prog = progress or (lambda stage, pct: None)
        with self.db.session() as s:
            ev = s.get(Evidence, evidence_id)
            if ev is None:
                raise NotFound("Evidence not found.")
            case = self.case_for(s, actor, ev.case_id)
            case_id, tz = ev.case_id, case.timezone
            check = self.ctx.evidence._verify(s, actor.username, ev, "pre-analysis")
            if not check.ok:
                raise persist(IntegrityViolation("Evidence failed pre-analysis integrity verification; analysis aborted."))
            files = list(s.scalars(select(EvidenceFile).where(EvidenceFile.evidence_id == ev.id)))
            work = Path(ev.working_path)
            ev_uid = ev.uid
            removed = s.execute(delete(Artifact).where(Artifact.evidence_id == ev.id)).rowcount
            job = AnalysisJob(case_id=case_id, evidence_id=ev.id, started_by=actor.username, status="running")
            s.add(job)
            s.flush()
            job_id = job.id
            self.ctx.audit.log("analysis.start", actor, case_id=case_id, object_type="evidence", object_id=ev_uid,
                               details={"job": job_id, "previous_artifacts_removed": removed,
                                        "analyzers": only or "all"}, session=s)

        analyzers = [a for a in all_analyzers() if not only or a.name in only]
        specific = [a for a in analyzers if not a.fallback]
        fallbacks = [a for a in analyzers if a.fallback]
        counts: Counter = Counter()
        errors: list[str] = []
        inventory_entries = []
        pending: list[Artifact] = []
        cfg = self.ctx.config

        def flush():
            if pending:
                with self.db.session() as s2:
                    s2.add_all(pending)
                pending.clear()

        for i, ef in enumerate(files):
            prog(f"Analyzing {ef.virtual_path}", int(90 * i / max(1, len(files))))
            fctx = FileContext(path=work / ef.rel_path, rel_path=ef.rel_path, virtual_path=ef.virtual_path,
                               detected_type=ef.detected_type, size=ef.size, evidence_file_id=ef.id,
                               default_cc=cfg.default_country_code, default_tz=tz, sha256=ef.sha256, mtime=ef.mtime)
            fctx.derived_dir = work.parent / "derived" / f"file_{ef.id}"
            matched = []
            for a in specific:
                try:
                    if a.matches(fctx):
                        matched.append(a)
                except Exception as exc:  # noqa: BLE001 - untrusted content must not stop the job
                    errors.append(f"{a.name} probe failed on {ef.virtual_path}: {type(exc).__name__}")
            if not matched:
                matched = [a for a in fallbacks if self._safe_match(a, fctx)]
            for a in matched:
                try:
                    for rec in a.parse(fctx):
                        pending.append(record_to_artifact(rec, case_id=case_id, evidence_id=evidence_id,
                                                          evidence_file_id=ef.id, job_id=job_id,
                                                          source_path=ef.virtual_path, parser_name=a.name,
                                                          parser_version=a.version))
                        counts[a.name] += 1
                        if len(pending) >= BATCH:
                            flush()
                except Exception as exc:  # noqa: BLE001
                    log.debug("analyzer failure\n%s", traceback.format_exc())
                    errors.append(f"{a.name} failed on {ef.virtual_path}: {type(exc).__name__}: {str(exc)[:200]}")
            inventory_entries.append((fctx, [a.name for a in matched]))
        for rec in inventory_apps(inventory_entries):
            pending.append(record_to_artifact(rec, case_id=case_id, evidence_id=evidence_id, evidence_file_id=None,
                                              job_id=job_id, source_path="(application inventory)",
                                              parser_name="apps.inventory", parser_version="1.0"))
            counts["apps.inventory"] += 1
        flush()

        prog("Post-analysis integrity verification", 92)
        with self.db.session() as s:
            ev = s.get(Evidence, evidence_id)
            post = self.ctx.evidence._verify(s, actor.username, ev, "post-analysis")
            job = s.get(AnalysisJob, job_id)
            job.status = "completed" if not errors else "completed_with_errors"
            job.finished_at = utcnow()
            job.analyzers = {**dict(counts), "_processing_tool_version": __version__}
            job.artifact_count = sum(counts.values())
            job.errors = errors[:500]
            if post.ok and ev.status != "integrity_alert":
                ev.status = "analyzed"
            self.ctx.cases.touch(s, case_id)
            self.ctx.audit.log("analysis.complete", actor, case_id=case_id, object_type="evidence", object_id=ev_uid,
                               details={"job": job_id, "artifacts": job.artifact_count, "by_analyzer": dict(counts),
                                        "errors": len(errors), "post_integrity_ok": post.ok}, session=s)
        if correlate:
            prog("Correlation", 95)
            self.ctx.correlation.rebuild(actor, case_id)
        prog("Done", 100)
        return job_id

    @staticmethod
    def _safe_match(a, fctx) -> bool:
        try:
            return a.matches(fctx)
        except Exception:  # noqa: BLE001
            return False

    def job(self, actor, job_id: int) -> AnalysisJob:
        self.authorize(actor, Perm.VIEW_CASE)
        with self.db.session() as s:
            j = s.get(AnalysisJob, job_id)
            if j is None:
                raise NotFound("Job not found.")
            self.case_for(s, actor, j.case_id)
            return j

    def category_counts(self, actor, case_id: int) -> dict[str, int]:
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            return dict(s.execute(select(Artifact.category, func.count(Artifact.id))
                                  .where(Artifact.case_id == case_id).group_by(Artifact.category)).all())

    def artifact(self, actor, artifact_id: int) -> Artifact:
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        with self.db.session() as s:
            a = s.get(Artifact, artifact_id)
            if a is None:
                raise NotFound("Artifact not found.")
            self.case_for(s, actor, a.case_id)
            self.ctx.audit.log("artifact.view", actor, case_id=a.case_id, object_type="artifact",
                               object_id=a.id, session=s)
            return a
