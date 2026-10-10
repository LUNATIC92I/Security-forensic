"""Shared fixtures. All data used by the tests is synthetic (see lunatic_forensics/synthetic.py)."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from lunatic_forensics.analyzers.base import FileContext
from lunatic_forensics.core.config import AppConfig
from lunatic_forensics.core.hashing import sha256_file
from lunatic_forensics.ingest.safety import detect_type
from lunatic_forensics.services.context import AppContext

PW = "Adm1n!Passw0rd-Test"
logging.getLogger("lunatic_forensics.core.security").setLevel(logging.ERROR)


@pytest.fixture
def config(tmp_path) -> AppConfig:
    cfg = AppConfig(home=tmp_path / "home", default_country_code="33")
    cfg.limits.max_compression_ratio = 100
    return cfg


@pytest.fixture
def ctx(config):
    c = AppContext(config)
    yield c
    c.close()


@pytest.fixture
def admin(ctx):
    ctx.auth.bootstrap_admin("admin", PW, "Lab Administrator")
    return ctx.auth.authenticate("admin", PW)


@pytest.fixture
def users(ctx, admin):
    out = {"admin": admin}
    for name, role in (("inv", "investigator"), ("inv2", "investigator"), ("ana", "analyst"), ("aud", "auditor")):
        ctx.auth.create_user(admin, name, PW, role, name.upper())
        out[name] = ctx.auth.authenticate(name, PW)
    return out


@pytest.fixture
def case_id(ctx, users):
    cid = ctx.cases.create(users["inv"], "Synthetic case", "Test description", "Synthetic mandate 2026/001",
                           "Synthetic device of fictitious person", "Europe/Paris")
    ctx.cases.add_member(users["inv"], cid, "ana")
    return cid


def make_fc(path: Path, virtual: str | None = None, tz: str = "UTC") -> FileContext:
    path = Path(path)
    return FileContext(path=path, rel_path=path.name, virtual_path=virtual or path.name, detected_type=detect_type(path),
                       size=path.stat().st_size, default_cc="33", default_tz=tz, sha256=sha256_file(path))


@pytest.fixture
def fc():
    return make_fc
