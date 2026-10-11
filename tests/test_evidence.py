"""Evidence preservation, hashing and chain-of-custody tests."""
import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

from lunatic_forensics import synthetic as S
from lunatic_forensics.core.errors import ImportRejected, IntegrityViolation, PermissionDenied, ValidationError


def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def test_import_hashes_and_readonly(ctx, users, case_id, tmp_path):
    src = S.android_calllog(tmp_path / "calllog.db")
    ev_id = ctx.evidence.import_evidence(users["inv"], case_id, src, acquisition_method="logical export",
                                         tool_name="SyntheticTool", tool_version="1.2")
    ev = ctx.evidence.get(users["inv"], ev_id)
    assert ev.sha256 == _sha(src)
    assert ev.md5 == hashlib.md5(src.read_bytes()).hexdigest()
    assert ev.file_count == 1 and ev.uid.startswith("EV-")
    stored = Path(ev.stored_path)
    assert _sha(stored) == ev.sha256
    assert Path(ev.working_path, "calllog.db").exists()
    if sys.platform != "win32":
        assert not os.access(stored, os.W_OK) or os.geteuid() == 0
        assert not stat.S_IMODE(stored.stat().st_mode) & stat.S_IWUSR
    checks = ctx.evidence.checks(users["inv"], ev_id)
    assert checks[0].context == "import" and checks[0].ok
    audit = ctx.audit.entries(users["inv"], case_id=case_id, action_prefix="evidence.import")
    d = audit[0].details
    assert d["sha256"] == ev.sha256 and d["acquisition_tool"] == "SyntheticTool 1.2" and "processing_tool" in d


def test_tamper_detection_blocks_analysis(ctx, users, case_id, tmp_path):
    src = S.android_calllog(tmp_path / "calllog.db")
    ev_id = ctx.evidence.import_evidence(users["inv"], case_id, src)
    ev = ctx.evidence.get(users["inv"], ev_id)
    stored = Path(ev.stored_path)
    os.chmod(stored.parent, 0o700)
    os.chmod(stored, 0o600)
    with open(stored, "ab") as f:
        f.write(b"tampered")
    check = ctx.evidence.verify(users["ana"], ev_id)
    assert not check.ok and check.observed != check.expected
    assert ctx.evidence.get(users["inv"], ev_id).status == "integrity_alert"
    assert ctx.cases.integrity_alerts(users["inv"])
    with pytest.raises(IntegrityViolation):
        ctx.analysis.run(users["inv"], ev_id)
    # the failed pre-analysis check must be persisted despite the exception
    contexts = [c.context for c in ctx.evidence.checks(users["inv"], ev_id) if not c.ok]
    assert "pre-analysis" in contexts
    assert ctx.audit.entries(users["admin"], action_prefix="evidence.integrity_violation")


def test_working_copy_change_reported(ctx, users, case_id, tmp_path):
    ev_id = ctx.evidence.import_evidence(users["inv"], case_id, S.vcard(tmp_path / "c.vcf"))
    ev = ctx.evidence.get(users["inv"], ev_id)
    wc = Path(ev.working_path, "c.vcf")
    os.chmod(wc, 0o600)  # working copies inherit the read-only mode: tampering requires lifting it
    wc.write_text("modified")
    check = ctx.evidence.verify(users["inv"], ev_id)
    assert check.ok  # original untouched
    assert any("working copy differs" in d for d in check.details)


def test_missing_original_is_alert(ctx, users, case_id, tmp_path):
    ev_id = ctx.evidence.import_evidence(users["inv"], case_id, S.vcard(tmp_path / "c.vcf"))
    ev = ctx.evidence.get(users["inv"], ev_id)
    p = Path(ev.stored_path)
    os.chmod(p.parent, 0o700)
    os.chmod(p, 0o600)  # Windows: read-only attribute must be cleared before deletion
    p.unlink()
    assert ctx.evidence.verify(users["inv"], ev_id).observed == "MISSING"


def test_directory_import_manifest(ctx, users, case_id, tmp_path):
    from lunatic_forensics.core.hashing import hash_directory
    d = S.ios_backup(tmp_path / "ios")
    ev_id = ctx.evidence.import_evidence(users["inv"], case_id, d)
    ev = ctx.evidence.get(users["inv"], ev_id)
    assert ev.is_directory and ev.sha256 == hash_directory(d)[0]
    assert ev.container_type == "ios_backup"
    files = ctx.evidence.files(users["inv"], ev_id)
    assert any(f.virtual_path == "HomeDomain/Library/SMS/sms.db" for f in files)
    devs = ctx.devices.list(users["inv"], case_id)
    assert devs and devs[0].platform == "ios" and devs[0].os_version == "17.4"
    assert devs[0].identifiers["serial_number"] == "SYNTHSERIAL01"
    assert ctx.evidence.verify(users["inv"], ev_id).ok


def test_rejected_import_is_audited(ctx, users, case_id, tmp_path):
    with pytest.raises(ImportRejected) as ei:
        ctx.evidence.import_evidence(users["inv"], case_id, S.zip_traversal(tmp_path / "t.zip"))
    assert ei.value.risks
    assert ctx.audit.entries(users["admin"], action_prefix="evidence.import_rejected")
    assert ctx.evidence.list(users["inv"], case_id) == []


def test_permissions_and_closed_case(ctx, users, case_id, tmp_path):
    src = S.vcard(tmp_path / "c.vcf")
    with pytest.raises(PermissionDenied):
        ctx.evidence.import_evidence(users["ana"], case_id, src)
    ctx.cases.update(users["inv"], case_id, status="closed")
    with pytest.raises(ValidationError):
        ctx.evidence.import_evidence(users["inv"], case_id, src)


def test_working_file_access_is_logged(ctx, users, case_id, tmp_path):
    ev_id = ctx.evidence.import_evidence(users["inv"], case_id, S.vcard(tmp_path / "c.vcf"))
    ef = ctx.evidence.files(users["inv"], ev_id)[0]
    p = ctx.evidence.working_file_path(users["ana"], ef.id)
    assert p.exists()
    assert ctx.audit.entries(users["admin"], action_prefix="evidence.view")


def test_reanalysis_is_idempotent(ctx, users, case_id, tmp_path):
    ev_id = ctx.evidence.import_evidence(users["inv"], case_id, S.android_mmssms(tmp_path / "mmssms.db"))
    ctx.analysis.run(users["inv"], ev_id)
    n1 = sum(ctx.analysis.category_counts(users["inv"], case_id).values())
    ctx.analysis.run(users["ana"], ev_id)
    assert sum(ctx.analysis.category_counts(users["inv"], case_id).values()) == n1
    checks = [c.context for c in ctx.evidence.checks(users["inv"], ev_id)]
    assert checks.count("pre-analysis") == 2 and checks.count("post-analysis") == 2


def test_encrypted_backup_import_does_not_store_password(ctx, users, case_id, tmp_path):
    from sqlalchemy import text
    src = S.android_backup(tmp_path / "enc.ab", encrypted=True)
    with pytest.raises(ImportRejected):
        ctx.evidence.import_evidence(users["inv"], case_id, src)
    ev_id = ctx.evidence.import_evidence(users["inv"], case_id, src, container_password=S.SYNTH_BACKUP_PASSWORD)
    ctx.analysis.run(users["inv"], ev_id)
    assert ctx.analysis.category_counts(users["inv"], case_id)["message"] == 8
    entry = ctx.audit.entries(users["admin"], action_prefix="evidence.import")[0]
    assert entry.details["container_password_supplied"] is True
    with ctx.db.engine.connect() as con:
        dump = "\n".join(str(r) for t in ("audit_log", "evidence", "devices") for r in con.execute(text(f"SELECT * FROM {t}")))
    assert S.SYNTH_BACKUP_PASSWORD not in dump
    log = (ctx.config.logs_dir / "lunatic.log").read_text()
    assert S.SYNTH_BACKUP_PASSWORD not in log
