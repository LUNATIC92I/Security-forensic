"""Authentication, user management and session handling."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select

from ..core.errors import AuthenticationError, NotFound, SessionLocked, ValidationError, persist
from ..core.rbac import Perm, Role, require
from ..core.security import (hash_password, new_token, validate_password_policy, validate_username,
                             verify_password)
from ..core.timeutils import ensure_utc, utcnow
from ..storage.models import User


@dataclass
class AuthSession:
    user_id: int
    username: str
    role: str
    full_name: str
    token: str = field(default_factory=new_token)
    created_at: datetime = field(default_factory=utcnow)
    last_activity: datetime = field(default_factory=utcnow)
    locked: bool = False
    revoked: bool = False


class AuthService:
    def __init__(self, ctx):
        self.ctx = ctx
        self._sessions: dict[str, AuthSession] = {}

    # ------------------------------------------------------------ sessions
    def check(self, actor: AuthSession) -> None:
        if actor is None or actor.revoked:
            raise SessionLocked("No active session.")
        if actor.locked:
            raise SessionLocked("Session locked: re-enter your password.")
        timeout = timedelta(minutes=self.ctx.config.session_timeout_minutes)
        if utcnow() - actor.last_activity > timeout:
            actor.locked = True
            self.ctx.audit.log("security.session_locked_inactivity", actor)
            raise SessionLocked("Session locked after inactivity: re-enter your password.")
        actor.last_activity = utcnow()

    def lock(self, actor: AuthSession) -> None:
        actor.locked = True
        self.ctx.audit.log("security.session_locked", actor)

    def unlock(self, actor: AuthSession, password: str) -> None:
        with self.ctx.db.session() as s:
            user = s.get(User, actor.user_id)
            if user is None or not user.is_active or not verify_password(user.password_hash, password):
                self.ctx.audit.log("security.unlock_failed", actor, session=s)
                raise persist(AuthenticationError("Invalid password."))
        actor.locked = False
        actor.last_activity = utcnow()
        self.ctx.audit.log("security.session_unlocked", actor)

    def logout(self, actor: AuthSession) -> None:
        actor.revoked = True
        self._sessions.pop(actor.token, None)
        self.ctx.audit.log("auth.logout", actor)

    def session_for_token(self, token: str) -> AuthSession:
        sess = self._sessions.get(token)
        if sess is None:
            raise SessionLocked("Invalid or expired token.")
        self.check(sess)
        return sess

    # -------------------------------------------------------------- users
    def has_users(self) -> bool:
        with self.ctx.db.session() as s:
            return (s.scalar(select(func.count(User.id))) or 0) > 0

    def bootstrap_admin(self, username: str, password: str, full_name: str = "Administrator") -> int:
        """Create the first administrator. Only allowed on an empty user table."""
        if self.has_users():
            raise ValidationError("Bootstrap is only possible when no user exists.")
        uid = self._create(username, password, Role.ADMIN, full_name)
        self.ctx.audit.log("user.bootstrap_admin", username=username, object_type="user", object_id=uid)
        return uid

    def create_user(self, actor: AuthSession, username: str, password: str, role: Role | str,
                    full_name: str = "") -> int:
        self.check(actor)
        require(actor.role, Perm.MANAGE_USERS)
        uid = self._create(username, password, Role(role), full_name)
        self.ctx.audit.log("user.create", actor, object_type="user", object_id=uid,
                           details={"username": username, "role": Role(role).value})
        return uid

    def _create(self, username: str, password: str, role: Role, full_name: str) -> int:
        validate_username(username)
        validate_password_policy(password)
        with self.ctx.db.session() as s:
            if s.scalar(select(User.id).where(User.username == username)):
                raise ValidationError("Username already exists.")
            u = User(username=username, full_name=full_name[:200], role=role.value,
                     password_hash=hash_password(password))
            s.add(u)
            s.flush()
            return u.id

    def authenticate(self, username: str, password: str) -> AuthSession:
        """Verify credentials. Failure counters and security events are committed
        *before* the error is raised so they survive the failed attempt."""
        cfg = self.ctx.config
        error: str | None = None
        sess: AuthSession | None = None
        with self.ctx.db.session() as s:
            user = s.scalar(select(User).where(User.username == username))
            now = utcnow()
            if user is None:
                verify_password(hash_password("dummy-Passw0rd!"), password)  # similar timing
                self.ctx.audit.log("security.login_failed", username=username or "?",
                                   details={"reason": "unknown user"}, session=s)
                error = "Invalid username or password."
            elif not user.is_active:
                self.ctx.audit.log("security.login_failed", username=username,
                                   details={"reason": "disabled"}, session=s)
                error = "Account disabled."
            elif user.locked_until and ensure_utc(user.locked_until) > now:
                self.ctx.audit.log("security.login_failed", username=username,
                                   details={"reason": "locked"}, session=s)
                error = "Account temporarily locked after repeated failures."
            elif not verify_password(user.password_hash, password):
                user.failed_attempts += 1
                details = {"reason": "bad password", "attempts": user.failed_attempts}
                if user.failed_attempts >= cfg.max_failed_logins:
                    user.locked_until = now + timedelta(minutes=cfg.lockout_minutes)
                    user.failed_attempts = 0
                    details["locked_until"] = user.locked_until.isoformat()
                    self.ctx.audit.log("security.account_locked", username=username, details=details, session=s)
                self.ctx.audit.log("security.login_failed", username=username, details=details, session=s)
                error = "Invalid username or password."
            else:
                user.failed_attempts = 0
                user.locked_until = None
                user.last_login = now
                sess = AuthSession(user.id, user.username, user.role, user.full_name)
                self._sessions[sess.token] = sess
                self.ctx.audit.log("auth.login", sess, session=s)
        if error:
            raise AuthenticationError(error)
        return sess

    def change_password(self, actor: AuthSession, old: str, new: str) -> None:
        self.check(actor)
        validate_password_policy(new)
        with self.ctx.db.session() as s:
            user = s.get(User, actor.user_id)
            if not verify_password(user.password_hash, old):
                raise AuthenticationError("Current password is incorrect.")
            user.password_hash = hash_password(new)
            self.ctx.audit.log("user.password_changed", actor, object_type="user", object_id=user.id, session=s)

    def reset_password(self, actor: AuthSession, user_id: int, new: str) -> None:
        self.check(actor)
        require(actor.role, Perm.MANAGE_USERS)
        validate_password_policy(new)
        with self.ctx.db.session() as s:
            user = s.get(User, user_id)
            if user is None:
                raise NotFound("User not found.")
            user.password_hash = hash_password(new)
            user.failed_attempts = 0
            user.locked_until = None
            self.ctx.audit.log("user.password_reset", actor, object_type="user", object_id=user_id, session=s)

    def set_active(self, actor: AuthSession, user_id: int, active: bool) -> None:
        self.check(actor)
        require(actor.role, Perm.MANAGE_USERS)
        if user_id == actor.user_id and not active:
            raise ValidationError("You cannot disable your own account.")
        with self.ctx.db.session() as s:
            user = s.get(User, user_id)
            if user is None:
                raise NotFound("User not found.")
            user.is_active = active
            self.ctx.audit.log("user.enable" if active else "user.disable", actor,
                               object_type="user", object_id=user_id, session=s)

    def set_role(self, actor: AuthSession, user_id: int, role: Role | str) -> None:
        self.check(actor)
        require(actor.role, Perm.MANAGE_USERS)
        with self.ctx.db.session() as s:
            user = s.get(User, user_id)
            if user is None:
                raise NotFound("User not found.")
            if user_id == actor.user_id and Role(role) != Role.ADMIN:
                raise ValidationError("You cannot remove your own administrator role.")
            user.role = Role(role).value
            self.ctx.audit.log("user.role_changed", actor, object_type="user", object_id=user_id,
                               details={"role": Role(role).value}, session=s)

    def list_users(self, actor: AuthSession) -> list[User]:
        self.check(actor)
        with self.ctx.db.session() as s:
            return list(s.scalars(select(User).order_by(User.username)))
