"""Investigation case management and dashboard statistics."""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..core.errors import NotFound, ValidationError
from ..core.rbac import Perm, has_perm
from ..core.timeutils import utcnow
from ..storage.models import (AnalysisJob, Artifact, Case, CaseMember, Device, Evidence,
                              IntegrityCheck, User)
from .base import ServiceBase

CASE_STATUSES = ("open", "in_progress", "suspended", "closed", "archived")


@dataclass
class CaseSummary:
    id: int
    uid: str
    title: str
    status: str
    owner: str
    created_at: datetime
    updated_at: datetime
    members: list[str]
    devices: int
    evidence: int
    artifacts: int
    jobs_running: int
    jobs_done: int
    integrity_alerts: int


class CaseService(ServiceBase):
    def _new_uid(self, s) -> str:
        while True:
            uid = f"LMF-{utcnow().year}-{secrets.token_hex(3).upper()}"
            if not s.scalar(select(Case.id).where(Case.uid == uid)):
                return uid

    def create(self, actor, title: str, description: str = "", legal_authority: str = "",
               scope: str = "", timezone: str = "UTC") -> int:
        self.authorize(actor, Perm.CREATE_CASE)
        title = (title or "").strip()
        if not title or len(title) > 200:
            raise ValidationError("A case title (1-200 characters) is required.")
        try:
            ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValidationError(f"Unknown timezone '{timezone}'.")
        with self.db.session() as s:
            case = Case(uid=self._new_uid(s), title=title, description=description,
                        legal_authority=legal_authority[:300], scope=scope, timezone=timezone,
                        owner_id=actor.user_id)
            s.add(case)
            s.flush()
            s.add(CaseMember(case_id=case.id, user_id=actor.user_id))
            self.ctx.audit.log("case.create", actor, case_id=case.id, object_type="case",
                               object_id=case.uid, details={"title": title}, session=s)
            return case.id

    def get(self, actor, case_id: int) -> Case:
        self.authorize(actor, Perm.VIEW_CASE)
        with self.db.session() as s:
            case = self.case_for(s, actor, case_id)
            _ = case.owner.username
            return case

    def update(self, actor, case_id: int, **fields) -> None:
        self.authorize(actor, Perm.EDIT_CASE)
        allowed = {"title", "description", "legal_authority", "scope", "status", "timezone"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValidationError(f"Fields not editable: {', '.join(sorted(unknown))}")
        if "status" in fields and fields["status"] not in CASE_STATUSES:
            raise ValidationError("Invalid status.")
        if "title" in fields and not str(fields["title"]).strip():
            raise ValidationError("Title cannot be empty.")
        with self.db.session() as s:
            case = self.case_for(s, actor, case_id)
            changes = {}
            for k, v in fields.items():
                if getattr(case, k) != v:
                    changes[k] = "<encrypted>" if k == "description" else {"old": getattr(case, k), "new": v}
                    setattr(case, k, v)
            case.updated_at = utcnow()
            self.ctx.audit.log("case.update", actor, case_id=case_id, object_type="case",
                               object_id=case.uid, details=changes, session=s)

    def touch(self, s, case_id: int) -> None:
        case = s.get(Case, case_id)
        if case:
            case.updated_at = utcnow()

    def list_for_user(self, actor) -> list[Case]:
        self.authorize(actor, Perm.VIEW_CASE)
        with self.db.session() as s:
            q = select(Case).order_by(Case.updated_at.desc())
            if not has_perm(actor.role, Perm.VIEW_ALL_CASES):
                member_ids = select(CaseMember.case_id).where(CaseMember.user_id == actor.user_id)
                q = q.where((Case.owner_id == actor.user_id) | Case.id.in_(member_ids))
            return list(s.scalars(q))

    def add_member(self, actor, case_id: int, username: str) -> None:
        self.authorize(actor, Perm.MANAGE_MEMBERS)
        with self.db.session() as s:
            case = self.case_for(s, actor, case_id)
            user = s.scalar(select(User).where(User.username == username))
            if user is None:
                raise NotFound("User not found.")
            if s.scalar(select(CaseMember.id).where(CaseMember.case_id == case_id, CaseMember.user_id == user.id)):
                return
            s.add(CaseMember(case_id=case_id, user_id=user.id))
            self.ctx.audit.log("case.member_added", actor, case_id=case_id, object_type="user",
                               object_id=user.id, details={"username": username}, session=s)
            case.updated_at = utcnow()

    def remove_member(self, actor, case_id: int, username: str) -> None:
        self.authorize(actor, Perm.MANAGE_MEMBERS)
        with self.db.session() as s:
            case = self.case_for(s, actor, case_id)
            user = s.scalar(select(User).where(User.username == username))
            if user is None:
                raise NotFound("User not found.")
            if user.id == case.owner_id:
                raise ValidationError("The case owner cannot be removed.")
            m = s.scalar(select(CaseMember).where(CaseMember.case_id == case_id, CaseMember.user_id == user.id))
            if m:
                s.delete(m)
                self.ctx.audit.log("case.member_removed", actor, case_id=case_id, object_type="user",
                                   object_id=user.id, details={"username": username}, session=s)

    def members(self, actor, case_id: int) -> list[str]:
        self.authorize(actor, Perm.VIEW_CASE)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            return list(s.scalars(select(User.username).join(CaseMember, CaseMember.user_id == User.id)
                                  .where(CaseMember.case_id == case_id).order_by(User.username)))

    def dashboard(self, actor) -> list[CaseSummary]:
        cases = self.list_for_user(actor)
        out = []
        with self.db.session() as s:
            for c in cases:
                members = list(s.scalars(select(User.username).join(CaseMember, CaseMember.user_id == User.id)
                                         .where(CaseMember.case_id == c.id)))
                owner = s.get(User, c.owner_id)
                ev_ids = select(Evidence.id).where(Evidence.case_id == c.id)
                alerts = s.scalar(select(func.count(IntegrityCheck.id)).where(
                    IntegrityCheck.evidence_id.in_(ev_ids), IntegrityCheck.ok.is_(False))) or 0
                out.append(CaseSummary(
                    id=c.id, uid=c.uid, title=c.title, status=c.status, owner=owner.username if owner else "?",
                    created_at=c.created_at, updated_at=c.updated_at, members=members,
                    devices=s.scalar(select(func.count(Device.id)).where(Device.case_id == c.id)) or 0,
                    evidence=s.scalar(select(func.count(Evidence.id)).where(Evidence.case_id == c.id)) or 0,
                    artifacts=s.scalar(select(func.count(Artifact.id)).where(Artifact.case_id == c.id)) or 0,
                    jobs_running=s.scalar(select(func.count(AnalysisJob.id)).where(
                        AnalysisJob.case_id == c.id, AnalysisJob.status == "running")) or 0,
                    jobs_done=s.scalar(select(func.count(AnalysisJob.id)).where(
                        AnalysisJob.case_id == c.id, AnalysisJob.status != "running")) or 0,
                    integrity_alerts=alerts,
                ))
        return out

    def integrity_alerts(self, actor) -> list[dict]:
        cases = {c.id: c for c in self.list_for_user(actor)}
        if not cases:
            return []
        with self.db.session() as s:
            rows = s.execute(select(IntegrityCheck, Evidence).join(Evidence, Evidence.id == IntegrityCheck.evidence_id)
                             .where(Evidence.case_id.in_(list(cases)), IntegrityCheck.ok.is_(False))
                             .order_by(IntegrityCheck.checked_at.desc())).all()
            return [{"case": cases[e.case_id].uid, "evidence": e.uid, "name": e.original_name,
                     "checked_at": ic.checked_at, "context": ic.context, "expected": ic.expected,
                     "observed": ic.observed} for ic, e in rows]

    def jobs(self, actor, case_id: int | None = None) -> list[AnalysisJob]:
        cases = [c.id for c in self.list_for_user(actor)]
        with self.db.session() as s:
            q = select(AnalysisJob).where(AnalysisJob.case_id.in_(cases))
            if case_id is not None:
                q = q.where(AnalysisJob.case_id == case_id)
            return list(s.scalars(q.order_by(AnalysisJob.started_at.desc()).limit(200)))
