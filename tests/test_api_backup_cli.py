import os

import pytest

from lunatic_forensics import synthetic as S
from lunatic_forensics.api.server import create_app, ensure_loopback
from lunatic_forensics.cli import main as cli_main
from lunatic_forensics.core.errors import ForensicError, ValidationError
from lunatic_forensics.services.backup_service import BackupService

from .conftest import PW


def test_api(ctx, users, case_id, tmp_path):
    from fastapi.testclient import TestClient
    ev = ctx.evidence.import_evidence(users["inv"], case_id, S.android_calllog(tmp_path / "c.db"))
    ctx.analysis.run(users["inv"], ev)
    c = TestClient(create_app(ctx))
    assert c.get("/health").json()["status"] == "ok"
    assert c.get("/cases").status_code == 401
    assert c.post("/auth/login", json={"username": "ana", "password": "nope"}).status_code == 401
    tok = c.post("/auth/login", json={"username": "ana", "password": PW}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert c.get("/cases", headers=h).json()[0]["id"] == case_id
    r = c.get(f"/cases/{case_id}/search", params={"phone": "0639980001"}, headers=h).json()
    assert r["total"] >= 1 and r["hits"][0]["source_table"] == "calls"
    assert c.get(f"/cases/{case_id}/search", params={"sha256": "zz"}, headers=h).status_code == 422
    assert all(x["ok"] for x in c.post(f"/cases/{case_id}/verify", headers=h).json())
    assert c.get("/audit/verify", headers=h).status_code == 403  # analyst lacks VIEW_AUDIT
    tok2 = c.post("/auth/login", json={"username": "inv2", "password": PW}).json()["token"]
    assert c.get(f"/cases/{case_id}/evidence", headers={"Authorization": f"Bearer {tok2}"}).status_code == 404
    tok3 = c.post("/auth/login", json={"username": "aud", "password": PW}).json()["token"]
    assert c.get("/audit/verify", headers={"Authorization": f"Bearer {tok3}"}).json()["intact"]
    c.post("/auth/logout", headers=h)
    assert c.get("/cases", headers=h).status_code == 401


def test_api_loopback_only(monkeypatch):
    monkeypatch.delenv("LUNATIC_API_ALLOW_REMOTE", raising=False)
    ensure_loopback("127.0.0.1")
    ensure_loopback("::1")
    with pytest.raises(ValidationError):
        ensure_loopback("0.0.0.0")


def test_backup_restore_and_tamper(ctx, users, case_id, tmp_path):
    ctx.evidence.import_evidence(users["inv"], case_id, S.vcard(tmp_path / "c.vcf"))
    with pytest.raises(Exception):
        ctx.backup.create(users["inv"], "Backup!Passphrase1", tmp_path / "bk")  # not admin
    bk = ctx.backup.create(users["admin"], "Backup!Passphrase1", tmp_path / "bk")
    files = BackupService.restore(bk, "Backup!Passphrase1", tmp_path / "restored", ctx.config.limits)
    assert "lunatic.db" in files and any(f.startswith("vault/") for f in files) and "keys/master.key" in files
    with pytest.raises(ForensicError):
        BackupService.restore(bk, "Wrong!Passphrase1", tmp_path / "r2", ctx.config.limits)
    data = bytearray(bk.read_bytes())
    data[len(data) // 2] ^= 0xFF
    (tmp_path / "tampered.lmfbak").write_bytes(bytes(data))
    with pytest.raises(ForensicError):
        BackupService.restore(tmp_path / "tampered.lmfbak", "Backup!Passphrase1", tmp_path / "r3", ctx.config.limits)
    (tmp_path / "trunc.lmfbak").write_bytes(bk.read_bytes()[:-40])
    with pytest.raises(ForensicError):
        BackupService.restore(tmp_path / "trunc.lmfbak", "Backup!Passphrase1", tmp_path / "r4", ctx.config.limits)
    with pytest.raises(ValidationError):
        BackupService.restore(bk, "Backup!Passphrase1", tmp_path / "restored", ctx.config.limits)  # not empty

    # restored installation is usable
    from lunatic_forensics.core.config import AppConfig
    from lunatic_forensics.services.context import AppContext
    ctx2 = AppContext(AppConfig(home=tmp_path / "restored"))
    a = ctx2.auth.authenticate("admin", PW)
    assert ctx2.cases.get(a, case_id).description == "Test description"
    ctx2.close()


def test_cli_workflow(tmp_path, monkeypatch, capsys):
    home = str(tmp_path / "clihome")
    monkeypatch.setenv("LUNATIC_PASSWORD", PW)
    assert cli_main(["--home", home, "init", "--admin", "boss"]) == 0
    assert cli_main(["--home", home, "--user", "boss", "case-create", "CLI case", "--timezone", "Europe/Paris"]) == 0
    src = S.android_mmssms(tmp_path / "mmssms.db")
    assert cli_main(["--home", home, "--user", "boss", "import", "1", str(src), "--analyze"]) == 0
    assert cli_main(["--home", home, "--user", "boss", "search", "1", "--phone", "0639980002"]) == 0
    out = capsys.readouterr().out
    assert "result(s)" in out and "source:" in out
    assert cli_main(["--home", home, "--user", "boss", "verify", "1"]) == 0
    assert cli_main(["--home", home, "--user", "boss", "report", "1", "--format", "html",
                     "--output", str(tmp_path / "r.html")]) == 0
    assert (tmp_path / "r.html").exists()
    bad = S.zip_traversal(tmp_path / "t.zip")
    assert cli_main(["--home", home, "--user", "boss", "import", "1", str(bad)]) == 2
    monkeypatch.setenv("LUNATIC_PASSWORD", "wrong")
    assert cli_main(["--home", home, "--user", "boss", "case-list"]) == 1
