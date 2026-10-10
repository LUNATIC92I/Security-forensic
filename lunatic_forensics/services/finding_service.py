"""Examiner findings: facts, interpretations and hypotheses linked to artefacts."""
from __future__ import annotations

from sqlalchemy import select

from ..core.errors import NotFound, ValidationError
from ..core.rbac import Perm
from ..storage.models import Artifact, Finding
from .base import ServiceBase

KINDS = ("fact", "interpretation", "hypothesis")


class FindingService(ServiceBase):
    def add(self, actor, case_id: int, kind: str, title: str, text: str, artifact_ids: list[int]) -> int:
        self.authorize(actor, Perm.WRITE_FINDINGS)
        if kind not in KINDS:
            raise ValidationError(f"Finding kind must be one of {', '.join(KINDS)}.")
        if not title.strip():
            raise ValidationError("A title is required.")
        ids = sorted({int(i) for i in artifact_ids})
        if kind == "fact" and not ids:
            raise ValidationError("A fact must reference at least one artefact.")
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            if ids:
                found = set(s.scalars(select(Artifact.id).where(Artifact.case_id == case_id, Artifact.id.in_(ids))))
                missing = set(ids) - found
                if missing:
                    raise ValidationError(f"Artefacts not in this case: {sorted(missing)[:10]}")
            f = Finding(case_id=case_id, author=actor.username, kind=kind, title=title.strip()[:300], text=text,
                        artifact_ids=ids)
            s.add(f)
            s.flush()
            self.ctx.audit.log("finding.add", actor, case_id=case_id, object_type="finding", object_id=f.id,
                               details={"kind": kind, "artifacts": ids[:100]}, session=s)
            return f.id

    def list(self, actor, case_id: int) -> list[Finding]:
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            return list(s.scalars(select(Finding).where(Finding.case_id == case_id).order_by(Finding.id)))

    def delete(self, actor, finding_id: int) -> None:
        self.authorize(actor, Perm.WRITE_FINDINGS)
        with self.db.session() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise NotFound("Finding not found.")
            self.case_for(s, actor, f.case_id)
            self.ctx.audit.log("finding.delete", actor, case_id=f.case_id, object_type="finding", object_id=f.id,
                               details={"title": f.title, "kind": f.kind}, session=s)
            s.delete(f)
