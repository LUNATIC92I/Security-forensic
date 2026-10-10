"""Encrypted backups of the application data (database, keys, vault).

Format ``.lmfbak``: ``MAGIC(8) | salt(16) | frames``. Each frame is
``len(4, big-endian) | nonce(12) | AES-256-GCM(ciphertext+tag)`` with AAD =
``MAGIC | frame index | final flag``: frames cannot be reordered, dropped or
truncated without detection. The key is derived from a passphrase (scrypt).
For PostgreSQL deployments, use ``pg_dump``; only the vault/keys are archived.
"""
from __future__ import annotations

import io
import os
import secrets
import sqlite3
import struct
import tarfile
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core.errors import ForensicError, ValidationError
from ..core.hashing import sha256_file
from ..core.rbac import Perm
from ..core.security import derive_key, validate_password_policy
from ..core.timeutils import utcnow
from ..ingest.safety import safe_extract_tar_stream
from .base import ServiceBase

MAGIC = b"LMFBAK01"
FRAME = 4 * 1024 * 1024


class _EncWriter(io.RawIOBase):
    def __init__(self, fh, key: bytes):
        self.fh, self.aes, self.buf, self.idx = fh, AESGCM(key), bytearray(), 0

    def writable(self):
        return True

    def write(self, b):
        self.buf += b
        while len(self.buf) > FRAME:
            self._frame(bytes(self.buf[:FRAME]), False)
            del self.buf[:FRAME]
        return len(b)

    def _frame(self, data: bytes, final: bool):
        nonce = secrets.token_bytes(12)
        ct = self.aes.encrypt(nonce, data, MAGIC + struct.pack(">Q?", self.idx, final))
        self.fh.write(struct.pack(">I", len(ct)) + nonce + ct)
        self.idx += 1

    def finish(self):
        self._frame(bytes(self.buf), True)
        self.buf.clear()


def _decrypt_frames(fh, key: bytes):
    aes = AESGCM(key)
    idx = 0
    while True:
        hdr = fh.read(4)
        if len(hdr) < 4:
            raise ForensicError("Backup truncated (no final frame).")
        (ln,) = struct.unpack(">I", hdr)
        nonce = fh.read(12)
        ct = fh.read(ln)
        for final in (False, True):
            try:
                data = aes.decrypt(nonce, ct, MAGIC + struct.pack(">Q?", idx, final))
                break
            except InvalidTag:
                data = None
        if data is None:
            raise ForensicError("Backup authentication failed (wrong passphrase or tampered file).")
        yield data
        idx += 1
        if final:
            return


class _FrameReader(io.RawIOBase):
    def __init__(self, gen):
        self.gen, self.buf = gen, b""

    def readable(self):
        return True

    def readinto(self, b):
        while not self.buf:
            try:
                self.buf = next(self.gen)
            except StopIteration:
                return 0
        n = min(len(b), len(self.buf))
        b[:n] = self.buf[:n]
        self.buf = self.buf[n:]
        return n


class BackupService(ServiceBase):
    def create(self, actor, passphrase: str, dest_dir: Path | None = None) -> Path:
        self.authorize(actor, Perm.BACKUP)
        validate_password_policy(passphrase)
        cfg = self.ctx.config
        dest_dir = Path(dest_dir or cfg.backups_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / f"lunatic_backup_{utcnow().strftime('%Y%m%dT%H%M%SZ')}.lmfbak"
        salt = secrets.token_bytes(16)
        key = derive_key(passphrase, salt)
        with tempfile.TemporaryDirectory() as tmp:
            db_snapshot = None
            url = cfg.resolved_database_url
            if url.startswith("sqlite:///"):
                db_snapshot = Path(tmp) / "lunatic.db"
                src = sqlite3.connect(url[len("sqlite:///"):])
                dst = sqlite3.connect(db_snapshot)
                src.backup(dst)
                src.close()
                dst.close()
            with open(out, "wb") as fh:
                fh.write(MAGIC + salt)
                w = _EncWriter(fh, key)
                with tarfile.open(fileobj=w, mode="w|gz") as tf:
                    if db_snapshot:
                        tf.add(db_snapshot, arcname="lunatic.db")
                    if cfg.keys_dir.exists():
                        tf.add(cfg.keys_dir, arcname="keys")
                    if cfg.vault_dir.exists():
                        tf.add(cfg.vault_dir, arcname="vault")
                    if cfg.reports_dir.exists():
                        tf.add(cfg.reports_dir, arcname="reports")
                w.finish()
        try:
            os.chmod(out, 0o600)
        except OSError:  # pragma: no cover
            pass
        sha = sha256_file(out)
        self.ctx.audit.log("backup.create", actor, object_type="backup", object_id=out.name,
                           details={"sha256": sha, "database_included": url.startswith("sqlite")})
        return out

    @staticmethod
    def restore(backup_file: Path, passphrase: str, target_home: Path, limits) -> list[str]:
        """Restore into an EMPTY directory (never overwrites an existing installation)."""
        target_home = Path(target_home)
        if target_home.exists() and any(target_home.iterdir()):
            raise ValidationError("Restore target must be an empty directory.")
        target_home.mkdir(parents=True, exist_ok=True)
        with open(backup_file, "rb") as fh:
            if fh.read(8) != MAGIC:
                raise ForensicError("Not a LUNATIC backup file.")
            key = derive_key(passphrase, fh.read(16))
            reader = io.BufferedReader(_FrameReader(_decrypt_frames(fh, key)))
            with tarfile.open(fileobj=reader, mode="r|gz") as tf:
                stats = safe_extract_tar_stream(tf, target_home, limits)
        return stats.files
