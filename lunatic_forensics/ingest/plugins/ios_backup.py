"""iOS / iPadOS local backup (Finder / iTunes / libimobiledevice ``idevicebackup2``).

Supported: *unencrypted* backups using ``Manifest.db`` (iOS 10+). Files are
stored as ``<sha1[:2]>/<sha1>`` and mapped to ``<domain>/<relativePath>``
through the ``Files`` table. Encrypted backups require the backup password and
keybag unwrapping, which is **not implemented** - they are rejected with an
explicit message. Legacy ``Manifest.mbdb`` backups (iOS < 10) are not supported.
"""
from __future__ import annotations

import plistlib
import shutil
import sqlite3
from pathlib import Path

from ...core.errors import ImportRejected
from .base import ExtractedFile, ExtractionResult, ImportPlugin, PrecheckResult


def _load_plist(p: Path) -> dict:
    try:
        with open(p, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return {}


def device_info_from_backup(src: Path) -> dict:
    info = _load_plist(src / "Info.plist")
    manifest = _load_plist(src / "Manifest.plist")
    lockdown = manifest.get("Lockdown", {}) if isinstance(manifest.get("Lockdown"), dict) else {}
    out = {
        "platform": "ios",
        "device_name": info.get("Device Name") or lockdown.get("DeviceName"),
        "product_type": info.get("Product Type") or lockdown.get("ProductType"),
        "os_version": info.get("Product Version") or lockdown.get("ProductVersion"),
        "build_version": info.get("Build Version") or lockdown.get("BuildVersion"),
        "serial_number": info.get("Serial Number") or lockdown.get("SerialNumber"),
        "udid": info.get("Unique Identifier") or lockdown.get("UniqueDeviceID"),
        "imei": info.get("IMEI"),
        "phone_number": info.get("Phone Number"),
        "last_backup_date": str(info.get("Last Backup Date") or manifest.get("Date") or ""),
        "is_encrypted": bool(manifest.get("IsEncrypted", False)),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


class IosBackupPlugin(ImportPlugin):
    name = "ios_backup"
    description = "iOS local backup folder (unencrypted, Manifest.db format)."
    container_type = "ios_backup"

    def probe(self, src, detected):
        return detected == "directory" and (src / "Manifest.db").exists() or \
            detected == "directory" and (src / "Manifest.mbdb").exists()

    def precheck(self, src, detected, limits):
        res = PrecheckResult()
        if (src / "Manifest.mbdb").exists() and not (src / "Manifest.db").exists():
            res.blocking.append("Legacy iOS backup format (Manifest.mbdb, iOS < 10) is not supported.")
            return res
        info = device_info_from_backup(src)
        res.structure = {"device": info}
        if info.get("is_encrypted"):
            res.blocking.append("Encrypted iOS backup: decryption (backup password + keybag) is not "
                                "implemented. Provide an unencrypted backup made with authorisation.")
        try:
            con = sqlite3.connect(f"file:{(src / 'Manifest.db').as_posix()}?mode=ro", uri=True)
            n = con.execute("SELECT COUNT(*) FROM Files WHERE flags = 1").fetchone()[0]
            con.close()
            res.structure["files"] = n
            if n > limits.max_files:
                res.blocking.append("Too many files in backup.")
        except sqlite3.DatabaseError as exc:
            res.blocking.append(f"Manifest.db unreadable: {exc}")
        return res

    def extract(self, src, workdir, limits):
        info = device_info_from_backup(src)
        if info.get("is_encrypted"):
            raise ImportRejected("Encrypted iOS backups are not supported.")
        workdir.mkdir(parents=True, exist_ok=True)
        files, warnings = [], []
        con = sqlite3.connect(f"file:{(src / 'Manifest.db').as_posix()}?mode=ro", uri=True)
        try:
            rows = con.execute("SELECT fileID, domain, relativePath FROM Files WHERE flags = 1").fetchall()
        finally:
            con.close()
        for file_id, domain, rel in rows:
            if not file_id or len(file_id) < 3 or any(c not in "0123456789abcdef" for c in file_id.lower()):
                warnings.append(f"Invalid fileID skipped: {file_id!r}")
                continue
            stored = src / file_id[:2] / file_id
            if not stored.is_file() or stored.is_symlink():
                warnings.append(f"Missing file in backup: {domain}/{rel}")
                continue
            target_rel = f"{file_id[:2]}/{file_id}"
            target = workdir / target_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(stored, target)
            files.append(ExtractedFile(target_rel, f"{domain}/{rel}"))
        for meta in ("Info.plist", "Manifest.plist", "Manifest.db", "Status.plist"):
            if (src / meta).is_file():
                shutil.copy2(src / meta, workdir / meta)
                files.append(ExtractedFile(meta, f"_backup_metadata/{meta}"))
        return ExtractionResult(self.container_type, files, warnings, info)
