from sqlalchemy import text


def test_chain_intact(ctx, users, case_id):
    ok, broken, n = ctx.audit.verify_chain()
    assert ok and broken is None and n > 5


def test_modification_detected(ctx, users, case_id):
    with ctx.db.engine.begin() as con:
        con.execute(text("UPDATE audit_log SET username = 'mallory' WHERE id = 3"))
    ok, broken, _ = ctx.audit.verify_chain()
    assert not ok and broken == 3


def test_deletion_detected(ctx, users, case_id):
    with ctx.db.engine.begin() as con:
        con.execute(text("DELETE FROM audit_log WHERE id = 4"))
    ok, broken, _ = ctx.audit.verify_chain()
    assert not ok and broken == 5


def test_head_hash_changes(ctx, admin):
    h1 = ctx.audit.head_hash()
    ctx.audit.log("test.event", admin, details={"x": 1})
    assert ctx.audit.head_hash() != h1
