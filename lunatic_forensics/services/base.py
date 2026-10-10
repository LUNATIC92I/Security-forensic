"""Shared service helpers: session checks, permission and case access control."""
from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.errors import NotFound, PermissionDenied, persist
from ..core.rbac import Perm, has_perm, require
from ..storage.models import Case, CaseMember

if TYPE_CHECKING:  # pragma: no cover
    from .auth_service import AuthSession
    from .context import AppContext


class ServiceBase:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx

    @property
    def db(self):
        return self.ctx.db

    def authorize(self, actor: "AuthSession", perm: Perm | None = None) -> None:
        self.ctx.auth.check(actor)
        if perm is not None:
            try:
                require(actor.role, perm)
            except PermissionDenied:
                self.ctx.audit.log("security.permission_denied", actor, details={"permission": perm.value})
                raise

    def can_access_case(self, s: Session, actor: "AuthSession", case_id: int) -> bool:
        if has_perm(actor.role, Perm.VIEW_ALL_CASES):
            return s.get(Case, case_id) is not None
        case = s.get(Case, case_id)
        if case is None:
            return False
        if case.owner_id == actor.user_id:
            return True
        return s.scalar(select(CaseMember.id).where(CaseMember.case_id == case_id,
                                                    CaseMember.user_id == actor.user_id)) is not None

    def case_for(self, s: Session, actor: "AuthSession", case_id: int) -> Case:
        """Return the case if it exists and the actor may access it.

        Inaccessible cases are reported as not found so their existence is
        not disclosed to unauthorised users.
        """
        if not self.can_access_case(s, actor, case_id):
            self.ctx.audit.log("security.case_access_denied", actor, case_id=case_id, session=s)
            raise persist(NotFound("Case not found."))
        return s.get(Case, case_id)
