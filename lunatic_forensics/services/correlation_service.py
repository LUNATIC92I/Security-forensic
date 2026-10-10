"""Timeline, correlation and relationship analysis over stored artefacts."""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy import delete, select

from ..core.normalize import unpack_identifiers
from ..core.rbac import Perm
from ..core.timeutils import ensure_utc, utcnow
from ..correlation import engine
from ..storage.models import Artifact, Case, Correlation
from .base import ServiceBase


class CorrelationService(ServiceBase):
    def _events(self, s, case_id: int) -> list[engine.Ev]:
        rows = s.execute(select(Artifact.id, Artifact.category, Artifact.timestamp_utc, Artifact.identifiers,
                                Artifact.names, Artifact.content_hash, Artifact.evidence_id, Artifact.direction,
                                Artifact.latitude, Artifact.longitude, Artifact.summary)
                         .where(Artifact.case_id == case_id, Artifact.is_recovered.is_(False))).all()
        out = []
        for r in rows:
            out.append(engine.Ev(id=r.id, category=r.category, ts=ensure_utc(r.timestamp_utc),
                                 identifiers=unpack_identifiers(r.identifiers),
                                 names=[n for n in (r.names or "").split("|") if n], content_hash=r.content_hash,
                                 evidence_id=r.evidence_id, direction=r.direction, lat=r.latitude, lon=r.longitude,
                                 summary=r.summary))
        return out

    def rebuild(self, actor, case_id: int) -> int:
        self.authorize(actor, Perm.RUN_ANALYSIS)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            events = self._events(s, case_id)
            media_mtimes = {}
            for a in s.scalars(select(Artifact).where(Artifact.case_id == case_id, Artifact.category == "media",
                                                      Artifact.timestamp_utc.is_not(None))):
                mt = (a.data or {}).get("interpreted", {}).get("file_mtime")
                if mt:
                    media_mtimes[a.id] = datetime.fromisoformat(mt)
            for e in events:
                e.file_mtime = media_mtimes.get(e.id)
            results = (engine.find_duplicates(events) + engine.group_contacts(events) + engine.link_contacts(events)
                       + engine.call_message_proximity(events) + engine.colocated_events(events)
                       + engine.temporal_anomalies(events, utcnow()))
            s.execute(delete(Correlation).where(Correlation.case_id == case_id))
            s.add_all([Correlation(case_id=case_id, kind=r.kind, rule=r.rule, description=r.description,
                                   artifact_ids=r.artifact_ids, score=r.score) for r in results])
            self.ctx.audit.log("correlation.rebuild", actor, case_id=case_id,
                               details={"results": len(results)}, session=s)
            return len(results)

    def correlations(self, actor, case_id: int, kind: str | None = None) -> list[Correlation]:
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            q = select(Correlation).where(Correlation.case_id == case_id)
            if kind:
                q = q.where(Correlation.kind == kind)
            return list(s.scalars(q.order_by(Correlation.kind, Correlation.rule, Correlation.id)))

    def timeline(self, actor, case_id: int, start: datetime | None = None, end: datetime | None = None,
                 categories: list[str] | None = None, limit: int = 1000, offset: int = 0,
                 include_recovered: bool = False) -> tuple[list[Artifact], int]:
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        from sqlalchemy import func
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            q = select(Artifact).where(Artifact.case_id == case_id, Artifact.timestamp_utc.is_not(None))
            if start:
                q = q.where(Artifact.timestamp_utc >= ensure_utc(start))
            if end:
                q = q.where(Artifact.timestamp_utc <= ensure_utc(end))
            if categories:
                q = q.where(Artifact.category.in_(categories))
            if not include_recovered:
                q = q.where(Artifact.is_recovered.is_(False))
            total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
            rows = list(s.scalars(q.order_by(Artifact.timestamp_utc, Artifact.id).offset(offset).limit(limit)))
            return rows, total

    def activity(self, actor, case_id: int, bucket: str = "day", categories: list[str] | None = None) -> dict:
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        with self.db.session() as s:
            case = self.case_for(s, actor, case_id)
            q = select(Artifact.timestamp_utc).where(Artifact.case_id == case_id, Artifact.timestamp_utc.is_not(None),
                                                     Artifact.is_recovered.is_(False))
            if categories:
                q = q.where(Artifact.category.in_(categories))
            ts = [ensure_utc(t) for t in s.scalars(q)]
            tz = ZoneInfo(case.timezone)
        return {"histogram": engine.histogram(ts, bucket, tz), "periods": engine.activity_periods(ts),
                "hour_of_day": engine.histogram(ts, "hour_of_day", tz), "timezone": str(tz)}

    def graph(self, actor, case_id: int) -> dict:
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            return engine.relationship_graph(self._events(s, case_id))
