from datetime import timedelta

import pytest
from sqlalchemy import text

from lunatic_forensics.core.errors import (AuthenticationError, NotFound, PermissionDenied, SessionLocked,
                                           ValidationError)
from lunatic_forensics.core.timeutils import utcnow

from .conftest import PW


def test_bootstrap_only_once(ctx, admin):
    with pytest.raises(ValidationError):
        ctx.auth.bootstrap_admin("other", PW)


def test_login_failures_and_lockout(ctx, admin):
    ctx.config.max_failed_logins = 3
    with pytest.raises(AuthenticationError):
        ctx.auth.authenticate("nobody", PW)
    for _ in range(3):
        with pytest.raises(AuthenticationError):
            ctx.auth.authenticate("admin", "Wrong!Passw0rd")
    with pytest.raises(AuthenticationError, match="locked"):
        ctx.auth.authenticate("admin", PW)  # correct password but account locked
    entries = ctx.audit.entries(admin, action_prefix="security.login_failed")
    assert len(entries) >= 5


def test_disabled_user(ctx, users):
    ctx.auth.set_active(users["admin"], users["ana"].user_id, False)
    with pytest.raises(AuthenticationError, match="disabled"):
        ctx.auth.authenticate("ana", PW)
    with pytest.raises(ValidationError):
        ctx.auth.set_active(users["admin"], users["admin"].user_id, False)


def test_only_admin_manages_users(ctx, users):
    with pytest.raises(PermissionDenied):
        ctx.auth.create_user(users["inv"], "x_user", PW, "analyst")


def test_session_timeout_lock_and_unlock(ctx, users):
    s = users["inv"]
    s.last_activity = utcnow() - timedelta(minutes=ctx.config.session_timeout_minutes + 1)
    with pytest.raises(SessionLocked):
        ctx.cases.list_for_user(s)
    assert s.locked
    with pytest.raises(AuthenticationError):
        ctx.auth.unlock(s, "bad")
    ctx.auth.unlock(s, PW)
    assert ctx.cases.list_for_user(s) == []
    ctx.auth.lock(s)
    with pytest.raises(SessionLocked):
        ctx.cases.list_for_user(s)
    ctx.auth.unlock(s, PW)
    ctx.auth.logout(s)
    with pytest.raises(SessionLocked):
        ctx.cases.list_for_user(s)


def test_change_password(ctx, users):
    ctx.auth.change_password(users["ana"], PW, "N3w!Password-123")
    ctx.auth.authenticate("ana", "N3w!Password-123")
    with pytest.raises(AuthenticationError):
        ctx.auth.change_password(users["ana"], "wrong", "N3w!Password-456")


def test_role_permissions(ctx, users, case_id):
    with pytest.raises(PermissionDenied):
        ctx.cases.create(users["ana"], "Not allowed")
    with pytest.raises(PermissionDenied):
        ctx.analysis.category_counts(users["aud"], case_id)
    # auditor sees cases & audit but not content
    assert any(c.id == case_id for c in ctx.cases.list_for_user(users["aud"]))
    assert ctx.audit.entries(users["aud"])


def test_case_isolation(ctx, users, case_id):
    with pytest.raises(NotFound):
        ctx.cases.get(users["inv2"], case_id)
    assert ctx.cases.list_for_user(users["inv2"]) == []
    assert ctx.audit.entries(users["admin"], action_prefix="security.case_access_denied")
    ctx.cases.add_member(users["inv"], case_id, "inv2")
    assert ctx.cases.get(users["inv2"], case_id).id == case_id
    ctx.cases.remove_member(users["inv"], case_id, "inv2")
    with pytest.raises(NotFound):
        ctx.cases.get(users["inv2"], case_id)
    with pytest.raises(ValidationError):
        ctx.cases.remove_member(users["inv"], case_id, "inv")


def test_case_fields_and_history(ctx, users, case_id):
    c = ctx.cases.get(users["inv"], case_id)
    assert c.uid.startswith("LMF-") and c.status == "open" and c.description == "Test description"
    ctx.cases.update(users["inv"], case_id, status="in_progress", title="Renamed")
    with pytest.raises(ValidationError):
        ctx.cases.update(users["inv"], case_id, status="bogus")
    with pytest.raises(ValidationError):
        ctx.cases.update(users["inv"], case_id, owner_id=1)
    with pytest.raises(ValidationError):
        ctx.cases.create(users["inv"], "x", timezone="Mars/Olympus")
    hist = ctx.audit.entries(users["admin"], case_id=case_id)
    assert {"case.create", "case.update", "case.member_added"} <= {e.action for e in hist}
    dash = ctx.cases.dashboard(users["inv"])
    assert dash[0].title == "Renamed" and set(dash[0].members) == {"inv", "ana"}


def test_sensitive_fields_encrypted_at_rest(ctx, users, case_id):
    with ctx.db.engine.connect() as con:
        raw = con.execute(text("SELECT description FROM cases WHERE id = :i"), {"i": case_id}).scalar()
    assert raw and "Test description" not in raw
    assert ctx.cases.get(users["inv"], case_id).description == "Test description"


def test_migrations_idempotent(ctx):
    from lunatic_forensics.storage.migrations import LATEST, migrate
    assert migrate(ctx.db.engine) == LATEST
    assert ctx.schema_version == LATEST


def test_datetimes_are_timezone_aware(ctx, users, case_id):
    assert ctx.cases.get(users["inv"], case_id).created_at.tzinfo is not None
