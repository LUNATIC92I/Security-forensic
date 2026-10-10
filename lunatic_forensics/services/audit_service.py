"""Hash-chained audit trail.

Each entry stores the SHA-256 of its canonical content concatenated with the
hash of the previous entry. Any modification, deletion or insertion inside
the chain is detected by :meth:`AuditService.verify_chain`. This makes the
journal tamper-*evident*, not tamper-proof: an attacker with write access to
the database could rebuild the chain, which is why periodic export of the
latest hash (included in reports) is recommended.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.rbac import Perm
from ..core.timeutils import ensure_utc, utcnow
from ..storage.models import AuditEntry

if TYPE_CHECKING:  # pragma: no cover
    from .auth_service import AuthSession

log = logging.getLogger("lunatic.audit")
GENESIS = "0" * 64


def _entry_digest(prev_hash: str, ts, username, action, case_id, object_type, object_id, details) -> str:
    canonical = json.dumps({
        "ts": ensure_utc(ts).isoformat(), "user": username, "action": action, "case": case_id,
        "otype": object_type, "oid": str(object_id), "details": details,
    }, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class AuditService:
    def __init__(self, ctx):
        self.ctx = ctx

    def log(self, action: str, actor: "AuthSession | None" = None, *, case_id: int | None = None,
            object_type: str = "", object_id="", details: dict | None = None,
            session: Session | None = None, username: str | None = None) -> None:
        details = json.loads(json.dumps(details or {}, default=str))
        user = username or (actor.username if actor else "system")
        if session is not None:
            self._append(session, action, user, case_id, object_type, object_id, details)
        else:
            with self.ctx.db.session() as s:
                self._append(s, action, user, case_id, object_type, object_id, details)
        log.info("%s by %s case=%s %s:%s", action, user, case_id, object_type, object_id)

    def _append(self, s: Session, action, user, case_id, object_type, object_id, details):
        prev = s.scalar(select(AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1)) or GENESIS
        ts = utcnow()
        digest = _entry_digest(prev, ts, user, action, case_id, object_type, object_id, details)
        s.add(AuditEntry(timestamp=ts, username=user, action=action, case_id=case_id,
                         object_type=object_type, object_id=str(object_id), details=details,
                         prev_hash=prev, entry_hash=digest))
        s.flush()

    def verify_chain(self) -> tuple[bool, int | None, int]:
        """Return (ok, first_broken_entry_id, entries_checked)."""
        prev = GENESIS
        n = 0
        with self.ctx.db.session() as s:
            for e in s.scalars(select(AuditEntry).order_by(AuditEntry.id)):
                n += 1
                expected = _entry_digest(prev, e.timestamp, e.username, e.action, e.case_id,
                                         e.object_type, e.object_id, e.details)
                if e.prev_hash != prev or e.entry_hash != expected:
                    return False, e.id, n
                prev = e.entry_hash
        return True, None, n

    def head_hash(self) -> str:
        with self.ctx.db.session() as s:
            return s.scalar(select(AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1)) or GENESIS

    def entries(self, actor: "AuthSession", case_id: int | None = None, action_prefix: str | None = None,
                limit: int = 500, offset: int = 0) -> list[AuditEntry]:
        self.ctx.auth.check(actor)
        from ..core.rbac import require
        require(actor.role, Perm.VIEW_AUDIT)
        with self.ctx.db.session() as s:
            q = select(AuditEntry)
            if case_id is not None:
                q = q.where(AuditEntry.case_id == case_id)
            if action_prefix:
                q = q.where(AuditEntry.action.like(f"{action_prefix}%"))
            q = q.order_by(AuditEntry.id.desc()).offset(offset).limit(limit)
            return list(s.scalars(q))

    def count(self) -> int:
        with self.ctx.db.session() as s:
            return s.scalar(select(func.count(AuditEntry.id))) or 0
