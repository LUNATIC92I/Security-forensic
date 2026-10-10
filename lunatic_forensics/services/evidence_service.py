"""Evidence import, preservation and integrity verification (chain of custody).

Workflow for each source:

1. pre-import inspection (size, real type, structure, malicious-content risks)
2. SHA-256 (+ MD5 for interoperability) of the **source**
3. copy into the case vault ``originals/`` and re-hash: copy must match source
4. originals are made read-only; analysis only ever touches ``work/`` copies
5. container extraction (from the vault copy) + per-file inventory with hashes
6. every step is written to the hash-chained audit log; integrity checks are
   stored and can be replayed at any time (pre/post analysis, manual, report)

A matching hash shows that the preserved bytes did not change since import;
it does not by itself establish authenticity or legal admissibility, which
also depend on acquisition conditions and documented procedure.
"""
from __future__ import annotations

import os
import secrets
import shutil
import stat
from dataclasses import asdict
from pathlib import Path

from sqlalchemy import select

from .. import __app_name__, __version__
from ..core.errors import ImportRejected, IntegrityViolation, NotFound, ValidationError
from ..core.hashing import hash_directory, hash_file, iter_regular_files
from ..core.rbac import Perm
from ..core.timeutils import utcnow
from ..ingest.registry import PrecheckReport, precheck, select_plugin
from ..ingest.safety import detect_type
from ..storage.models import Case, Device, Evidence, EvidenceFile, IntegrityCheck
from .base import ServiceBase

from datetime import datetime, timezone


def _make_readonly(path: Path) -> None:
    if path.is_dir():
        for p in iter_regular_files(path):
            os.chmod(p, stat.S_IRUSR | stat.S_IRGRP)
        for dirpath, _dirs, _files in os.walk(path, topdown=False):
            os.chmod(dirpath, stat.S_IRUSR | stat.S_IXUSR)
    else:
        os.chmod(path, stat.S_IRUSR | stat.S_IRGRP)
        os.chmod(path.parent, stat.S_IRUSR | stat.S_IXUSR)


def force_rmtree(path: Path) -> None:
    """Remove a vault directory, restoring write permission first (aborted imports only)."""
    for dirpath, dirs, files in os.walk(path):
        os.chmod(dirpath, 0o700)
        for name in files:
            os.chmod(os.path.join(dirpath, name), 0o600)
    shutil.rmtree(path, ignore_errors=True)


class EvidenceService(ServiceBase):
    # ----------------------------------------------------------- inspection
    def precheck(self, actor, path: str | Path, password: str | None = None) -> PrecheckReport:
        self.authorize(actor, Perm.IMPORT_EVIDENCE)
        return precheck(Path(path), self.ctx.config.limits, password=password)

    # --------------------------------------------------------------- import
    def import_evidence(self, actor, case_id: int, path: str | Path, *, device_id: int | None = None,
                        acquisition_method: str = "file import", tool_name: str = "", tool_version: str = "",
                        notes: str = "", progress=None, container_password: str | None = None) -> int:
        """Import a source. ``container_password`` (encrypted backups) is used in memory for
        this import only: it is never stored nor logged; the audit records only that one was supplied."""
        self.authorize(actor, Perm.IMPORT_EVIDENCE)
        src = Path(path)
        prog = progress or (lambda stage, pct: None)
        with self.db.session() as s:
            case = self.case_for(s, actor, case_id)
            if case.status in ("closed", "archived"):
                raise ValidationError("Evidence cannot be added to a closed or archived case.")
            case_uid = case.uid
            if device_id is not None:
                dev = s.get(Device, device_id)
                if dev is None or dev.case_id != case_id:
                    raise ValidationError("Device does not belong to this case.")

        prog("Pre-import inspection", 5)
        report = precheck(src, self.ctx.config.limits, password=container_password)
        if not report.accepted:
            self.ctx.audit.log("evidence.import_rejected", actor, case_id=case_id, object_type="source",
                               object_id=src.name, details={"blocking": report.blocking, "type": report.detected_type})
            raise ImportRejected("Source rejected by pre-import checks.", report.blocking)

        ev_uid = f"EV-{secrets.token_hex(4).upper()}"
        base = self.ctx.config.vault_dir / case_uid / ev_uid
        original_dir = base / "original"
        work_dir = base / "work"
        original_dir.mkdir(parents=True, exist_ok=False)
        work_dir.mkdir(parents=True)

        prog("Hashing source", 15)
        is_dir = src.is_dir()
        if is_dir:
            src_sha, _entries, size = hash_directory(src)
            src_md5 = ""
        else:
            src_sha, src_md5, size = hash_file(src)

        prog("Copying to read-only vault", 30)
        stored = original_dir / src.name
        if is_dir:
            stored.mkdir()
            for p in iter_regular_files(src):
                t = stored / p.relative_to(src)
                t.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, t)
            copy_sha = hash_directory(stored)[0]
        else:
            shutil.copy2(src, stored)
            copy_sha = hash_file(stored, with_md5=False)[0]
        if copy_sha != src_sha:
            force_rmtree(base)
            self.ctx.audit.log("evidence.copy_mismatch", actor, case_id=case_id, object_type="source",
                               object_id=src.name, details={"source_sha256": src_sha, "copy_sha256": copy_sha})
            raise IntegrityViolation("Vault copy does not match the source hash: import aborted.")
        _make_readonly(stored)

        prog("Extracting working copy", 50)
        plugin = select_plugin(stored, report.detected_type)
        try:
            result = plugin.extract(stored, work_dir, self.ctx.config.limits, password=container_password)
        except ImportRejected as exc:
            self.ctx.audit.log("evidence.import_rejected", actor, case_id=case_id, object_type="source",
                               object_id=src.name, details={"stage": "extraction", "reason": str(exc), "risks": exc.risks})
            force_rmtree(base)
            raise

        prog("Inventory and hashing of extracted files", 70)
        files = []
        for i, ef in enumerate(result.files):
            p = work_dir / ef.rel_path
            if not p.is_file():
                continue
            sha, _, fsize = hash_file(p, with_md5=False)
            files.append(EvidenceFile(rel_path=ef.rel_path, virtual_path=ef.virtual_path or ef.rel_path, size=fsize,
                                      sha256=sha, detected_type=detect_type(p),
                                      mtime=datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)))
            if i % 200 == 0:
                prog("Inventory and hashing of extracted files", 70 + int(25 * i / max(1, len(result.files))))

        with self.db.session() as s:
            if device_id is None and result.device_info.get("platform"):
                info = result.device_info
                dev = Device(case_id=case_id, label=info.get("device_name") or f"{info['platform']} device ({ev_uid})",
                             platform=info["platform"], manufacturer="Apple" if info["platform"] == "ios" else "",
                             model=info.get("product_type", ""), os_version=info.get("os_version", ""),
                             identifiers={k: v for k, v in info.items() if k in ("serial_number", "udid", "imei", "phone_number")},
                             access_level="logical backup (unencrypted)", connection_state="offline (imported backup)",
                             limitations=["Content limited to what the backup mechanism includes",
                                          "No physical/file-system level access"],
                             collection_scope=f"Backup imported as {ev_uid}")
                s.add(dev)
                s.flush()
                device_id = dev.id
            ev = Evidence(uid=ev_uid, case_id=case_id, device_id=device_id, original_name=src.name,
                          source_path=str(src.resolve()), stored_path=str(stored), working_path=str(work_dir),
                          is_directory=is_dir, size=size, sha256=src_sha, md5=src_md5,
                          detected_type=report.detected_type, container_type=result.container_type,
                          acquisition_method=acquisition_method[:200], tool_name=tool_name[:100],
                          tool_version=tool_version[:50], notes=notes, file_count=len(files),
                          warnings=(report.warnings + result.warnings)[:500], imported_by=actor.user_id)
            ev.files = files
            s.add(ev)
            s.flush()
            s.add(IntegrityCheck(evidence_id=ev.id, checked_by=actor.username, context="import",
                                 expected=src_sha, observed=copy_sha, ok=True))
            self.ctx.cases.touch(s, case_id)
            self.ctx.audit.log("evidence.import", actor, case_id=case_id, object_type="evidence", object_id=ev_uid,
                               details={"name": src.name, "sha256": src_sha, "md5": src_md5, "size": size,
                                        "type": report.detected_type, "container": result.container_type,
                                        "files": len(files), "acquisition_method": acquisition_method,
                                        "acquisition_tool": f"{tool_name} {tool_version}".strip(),
                                        "processing_tool": f"{__app_name__} {__version__}",
                                        "plugin": plugin.name, "warnings": len(ev.warnings),
                                        "container_password_supplied": bool(container_password)}, session=s)
            ev_id = ev.id
        prog("Done", 100)
        return ev_id

    # --------------------------------------------------------------- access
    def list(self, actor, case_id: int) -> list[Evidence]:
        self.authorize(actor, Perm.VIEW_CASE)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            return list(s.scalars(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.imported_at)))

    def get(self, actor, evidence_id: int) -> Evidence:
        self.authorize(actor, Perm.VIEW_CASE)
        with self.db.session() as s:
            ev = s.get(Evidence, evidence_id)
            if ev is None:
                raise NotFound("Evidence not found.")
            self.case_for(s, actor, ev.case_id)
            return ev

    def files(self, actor, evidence_id: int, limit: int = 10000, offset: int = 0) -> list[EvidenceFile]:
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        ev = self.get(actor, evidence_id)
        with self.db.session() as s:
            return list(s.scalars(select(EvidenceFile).where(EvidenceFile.evidence_id == ev.id)
                                  .order_by(EvidenceFile.rel_path).offset(offset).limit(limit)))

    def working_file_path(self, actor, evidence_file_id: int) -> Path:
        """Return the working-copy path of an inventoried file (logged as a consultation)."""
        self.authorize(actor, Perm.VIEW_ARTIFACTS)
        with self.db.session() as s:
            ef = s.get(EvidenceFile, evidence_file_id)
            if ef is None:
                raise NotFound("File not found.")
            ev = s.get(Evidence, ef.evidence_id)
            self.case_for(s, actor, ev.case_id)
            p = (Path(ev.working_path) / ef.rel_path).resolve()
            if os.path.commonpath([str(Path(ev.working_path).resolve()), str(p)]) != str(Path(ev.working_path).resolve()):
                raise ValidationError("Invalid path.")
            self.ctx.audit.log("evidence.view", actor, case_id=ev.case_id, object_type="evidence_file",
                               object_id=ef.id, details={"evidence": ev.uid, "path": ef.virtual_path}, session=s)
            return p

    # ------------------------------------------------------------ integrity
    def verify(self, actor, evidence_id: int, context: str = "manual") -> IntegrityCheck:
        self.authorize(actor, Perm.VERIFY_INTEGRITY)
        with self.db.session() as s:
            ev = s.get(Evidence, evidence_id)
            if ev is None:
                raise NotFound("Evidence not found.")
            self.case_for(s, actor, ev.case_id)
            return self._verify(s, actor.username, ev, context)

    def _verify(self, s, username: str, ev: Evidence, context: str) -> IntegrityCheck:
        stored = Path(ev.stored_path)
        details = []
        if not stored.exists():
            observed = "MISSING"
        elif ev.is_directory:
            observed = hash_directory(stored)[0]
        else:
            observed = hash_file(stored, with_md5=False)[0]
        ok = observed == ev.sha256
        # working copies: report changes (originals remain the reference)
        work = Path(ev.working_path)
        changed = 0
        for ef in s.scalars(select(EvidenceFile).where(EvidenceFile.evidence_id == ev.id)):
            p = work / ef.rel_path
            if not p.exists() or hash_file(p, with_md5=False)[0] != ef.sha256:
                changed += 1
                if len(details) < 50:
                    details.append(f"working copy differs from inventory: {ef.virtual_path}")
        if changed > 50:
            details.append(f"... {changed - 50} more working files differ")
        check = IntegrityCheck(evidence_id=ev.id, checked_by=username, context=context, expected=ev.sha256,
                               observed=observed, ok=ok, details=details)
        s.add(check)
        if not ok:
            ev.status = "integrity_alert"
            self.ctx.audit.log("evidence.integrity_violation", username=username, case_id=ev.case_id,
                               object_type="evidence", object_id=ev.uid,
                               details={"expected": ev.sha256, "observed": observed, "context": context}, session=s)
        else:
            self.ctx.audit.log("evidence.integrity_verified", username=username, case_id=ev.case_id,
                               object_type="evidence", object_id=ev.uid,
                               details={"sha256": observed, "context": context, "working_changes": changed}, session=s)
        s.flush()
        return check

    def verify_case(self, actor, case_id: int, context: str = "manual") -> list[IntegrityCheck]:
        self.authorize(actor, Perm.VERIFY_INTEGRITY)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            return [self._verify(s, actor.username, ev, context)
                    for ev in s.scalars(select(Evidence).where(Evidence.case_id == case_id))]

    def checks(self, actor, evidence_id: int) -> list[IntegrityCheck]:
        self.authorize(actor, Perm.VIEW_CASE)
        ev = self.get(actor, evidence_id)
        with self.db.session() as s:
            return list(s.scalars(select(IntegrityCheck).where(IntegrityCheck.evidence_id == ev.id)
                                  .order_by(IntegrityCheck.checked_at)))


def precheck_as_dict(r: PrecheckReport) -> dict:
    return asdict(r)
