"""Forensic search with combinable filters, pagination and traceable results.

All SQL filters use bound parameters (SQLAlchemy expressions): user input is
never interpolated into SQL text. LIKE wildcards in user input are escaped.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, func, or_, select

from ..core.errors import ValidationError
from ..core.normalize import normalize_email, normalize_phone
from ..core.rbac import Perm
from ..core.timeutils import ensure_utc
from ..storage.models import Artifact, Evidence, EvidenceFile
from .base import ServiceBase

DEEP_SCAN_LIMIT = 200_000


class SearchQuery(BaseModel):
    text: str | None = None
    deep: bool = False                 # also scan encrypted full content (slower)
    phone: str | None = None
    email: str | None = None
    name: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    sha256: str | None = None
    categories: list[str] = Field(default_factory=list)
    mime: str | None = None
    conversation_id: str | None = None
    min_lat: float | None = None
    max_lat: float | None = None
    min_lon: float | None = None
    max_lon: float | None = None
    evidence_id: int | None = None
    include_recovered: bool = True
    page: int = 1
    page_size: int = 100

    @field_validator("page")
    @classmethod
    def _page(cls, v):
        if v < 1:
            raise ValueError("page must be >= 1")
        return v

    @field_validator("page_size")
    @classmethod
    def _ps(cls, v):
        if not 1 <= v <= 1000:
            raise ValueError("page_size must be between 1 and 1000")
        return v

    @field_validator("sha256")
    @classmethod
    def _sha(cls, v):
        if v is None or v == "":
            return None
        v = v.strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("sha256 must be 64 hexadecimal characters")
        return v

    @field_validator("text", "name", "conversation_id", "mime")
    @classmethod
    def _len(cls, v):
        if v is not None and len(v) > 500:
            raise ValueError("search term too long")
        return v or None


@dataclass
class SearchHit:
    artifact_id: int | None
    category: str
    subtype: str
    timestamp: datetime | None
    summary: str
    evidence_uid: str
    source_path: str
    source_table: str | None
    source_rowid: str | None
    parser: str
    sha256: str | None
    evidence_file_id: int | None = None


@dataclass
class SearchPage:
    hits: list[SearchHit]
    total: int
    page: int
    page_size: int
    file_hits: list[dict]

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.page_size))


def _like(v: str) -> str:
    return "%" + v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class SearchService(ServiceBase):
    def search(self, actor, case_id: int, q: SearchQuery) -> SearchPage:
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        cc = self.ctx.config.default_country_code
        conds = [Artifact.case_id == case_id]
        if q.phone:
            norm = normalize_phone(q.phone, cc)
            if not norm:
                raise ValidationError("Invalid phone number.")
            digits = norm.lstrip("+")
            conds.append(or_(Artifact.identifiers.like(_like(f"|{norm}|"), escape="\\"),
                             Artifact.identifiers.like(_like(digits[-9:]) if len(digits) >= 9 else _like(digits), escape="\\")))
        if q.email:
            norm = normalize_email(q.email)
            if not norm:
                raise ValidationError("Invalid e-mail address.")
            conds.append(Artifact.identifiers.like(_like(f"|{norm}|"), escape="\\"))
        if q.name:
            conds.append(or_(Artifact.names.ilike(_like(q.name), escape="\\"),
                             Artifact.summary.ilike(_like(q.name), escape="\\")))
        if q.start:
            conds.append(Artifact.timestamp_utc >= ensure_utc(q.start))
        if q.end:
            conds.append(Artifact.timestamp_utc <= ensure_utc(q.end))
        if q.sha256:
            conds.append(Artifact.sha256 == q.sha256)
        if q.categories:
            conds.append(Artifact.category.in_(q.categories))
        if q.mime:
            conds.append(or_(Artifact.mime.ilike(_like(q.mime), escape="\\"), Artifact.subtype.ilike(_like(q.mime), escape="\\")))
        if q.conversation_id:
            conds.append(Artifact.conversation_id.ilike(_like(q.conversation_id), escape="\\"))
        if None not in (q.min_lat, q.max_lat, q.min_lon, q.max_lon):
            conds.append(and_(Artifact.latitude.between(q.min_lat, q.max_lat),
                              Artifact.longitude.between(q.min_lon, q.max_lon)))
        if q.evidence_id:
            conds.append(Artifact.evidence_id == q.evidence_id)
        if not q.include_recovered:
            conds.append(Artifact.is_recovered.is_(False))

        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            evs = {e.id: e.uid for e in s.scalars(select(Evidence).where(Evidence.case_id == case_id))}
            base = select(Artifact).where(*conds)
            order = (Artifact.timestamp_utc.is_(None), Artifact.timestamp_utc, Artifact.id)
            if q.text and q.deep:
                ids = self._deep_ids(s, conds, q.text)
                total = len(ids)
                page_ids = ids[(q.page - 1) * q.page_size: q.page * q.page_size]
                rows = list(s.scalars(select(Artifact).where(Artifact.id.in_(page_ids)).order_by(*order))) if page_ids else []
            else:
                if q.text:
                    t = _like(q.text)
                    base = base.where(or_(Artifact.summary.ilike(t, escape="\\"), Artifact.names.ilike(t, escape="\\"),
                                          Artifact.identifiers.ilike(t, escape="\\"),
                                          Artifact.source_path.ilike(t, escape="\\")))
                total = s.scalar(select(func.count()).select_from(base.subquery())) or 0
                rows = list(s.scalars(base.order_by(*order).offset((q.page - 1) * q.page_size).limit(q.page_size)))
            hits = [SearchHit(a.id, a.category, a.subtype, a.timestamp_utc, a.summary, evs.get(a.evidence_id, "?"),
                              a.source_path, a.source_table, a.source_rowid, f"{a.parser_name} {a.parser_version}",
                              a.sha256, a.evidence_file_id) for a in rows]
            file_hits = []
            if q.sha256 or (q.text and len(q.text) >= 3 and q.page == 1):
                fq = select(EvidenceFile).where(EvidenceFile.evidence_id.in_(list(evs)))
                fq = fq.where(EvidenceFile.sha256 == q.sha256) if q.sha256 else \
                    fq.where(EvidenceFile.virtual_path.ilike(_like(q.text), escape="\\"))
                for ef in s.scalars(fq.limit(200)):
                    file_hits.append({"evidence_file_id": ef.id, "evidence": evs.get(ef.evidence_id), "path": ef.virtual_path,
                                      "sha256": ef.sha256, "size": ef.size, "type": ef.detected_type})
            self.ctx.audit.log("search.execute", actor, case_id=case_id,
                               details={"filters": q.model_dump(exclude_defaults=True, mode="json"), "total": total}, session=s)
        return SearchPage(hits, total, q.page, q.page_size, file_hits)

    def _deep_ids(self, s, conds, text: str) -> list[int]:
        needle = text.lower()
        ids = []
        rows = s.execute(select(Artifact.id, Artifact.summary, Artifact.names, Artifact.identifiers, Artifact.data)
                         .where(*conds).order_by(Artifact.timestamp_utc.is_(None), Artifact.timestamp_utc, Artifact.id)
                         .limit(DEEP_SCAN_LIMIT))
        for r in rows:
            hay = " ".join([r.summary or "", r.names or "", r.identifiers or ""]).lower()
            if needle in hay:
                ids.append(r.id)
                continue
            interp = (r.data or {}).get("interpreted", {})
            blob = " ".join(str(v) for v in interp.values() if isinstance(v, (str, int, float))).lower()
            if needle in blob:
                ids.append(r.id)
        return ids
