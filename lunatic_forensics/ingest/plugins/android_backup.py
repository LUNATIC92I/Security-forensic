"""Android ``adb backup`` (.ab) container.

Format (AOSP ``BackupManagerService`` / ``PerformAdbBackupTask``)::

    ANDROID BACKUP\\n<version>\\n<compressed 0|1>\\n<encryption: none|AES-256>\\n
    [AES-256 only] <user salt hex>\\n<checksum salt hex>\\n<PBKDF2 rounds>\\n<user IV hex>\\n<master key blob hex>\\n
    payload = [AES-256-CBC(master key, master IV)] ( [zlib] ( TAR ) )

Encrypted backups are decrypted **only with the backup password supplied by the
investigator** (owner consent or legal authority). The password is verified
through the documented master-key checksum before any extraction; it is never
stored and no password guessing is performed.

Key derivation: ``PBKDF2-HMAC-SHA1(password, user_salt, rounds, 256 bits)``
decrypts the master key blob ``[len|master IV][len|master key][len|checksum]``.
The checksum is ``PBKDF2(mangled(master key), checksum_salt, rounds)`` where,
for format version >= 2, each key byte is converted like a Java signed
``byte -> char`` and the resulting string UTF-8 encoded (behaviour of Android's
PBKDF2WithHmacSHA1And8bit implementation); version 1 uses the raw bytes.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ...core.errors import ImportRejected
from ..safety import safe_extract_tar_stream
from .base import ExtractedFile, ExtractionResult, ImportPlugin, PrecheckResult

MAX_ROUNDS = 1_000_000  # refuse absurd values from a hostile header (CPU exhaustion)


@dataclass
class AbHeader:
    version: int
    compressed: bool
    encryption: str
    offset: int
    user_salt: bytes = b""
    checksum_salt: bytes = b""
    rounds: int = 0
    user_iv: bytes = b""
    master_blob: bytes = b""

    @property
    def encrypted(self) -> bool:
        return self.encryption.lower() != "none"


def read_header(path: Path) -> AbHeader:
    with open(path, "rb") as f:
        lines = [f.readline(4096) for _ in range(4)]
        try:
            magic, version, compressed, enc = (l.decode("ascii").strip() for l in lines)
        except UnicodeDecodeError as exc:
            raise ImportRejected("Malformed Android backup header.") from exc
        if magic != "ANDROID BACKUP":
            raise ImportRejected("Not an Android backup file.")
        if not version.isdigit() or compressed not in ("0", "1"):
            raise ImportRejected("Malformed Android backup header.")
        h = AbHeader(int(version), compressed == "1", enc, 0)
        if h.encrypted:
            if enc != "AES-256":
                raise ImportRejected(f"Unsupported Android backup encryption '{enc}'.")
            try:
                extra = [f.readline(8192).decode("ascii").strip() for _ in range(5)]
                h.user_salt = bytes.fromhex(extra[0])
                h.checksum_salt = bytes.fromhex(extra[1])
                h.rounds = int(extra[2])
                h.user_iv = bytes.fromhex(extra[3])
                h.master_blob = bytes.fromhex(extra[4])
            except (ValueError, UnicodeDecodeError, IndexError) as exc:
                raise ImportRejected("Malformed encryption parameters in Android backup header.") from exc
            if not 1 <= h.rounds <= MAX_ROUNDS or len(h.user_iv) != 16 or not h.master_blob:
                raise ImportRejected("Implausible encryption parameters in Android backup header.")
        h.offset = f.tell()
    return h


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    raw = d.update(data) + d.finalize()
    u = padding.PKCS7(128).unpadder()
    return u.update(raw) + u.finalize()


def mangle_key(key: bytes, version: int) -> bytes:
    if version < 2:
        return key
    return "".join(chr(b | 0xFF00) if b >= 0x80 else chr(b) for b in key).encode("utf-8")


def unlock_master_key(h: AbHeader, password: str) -> tuple[bytes, bytes]:
    """Return (master_key, master_iv) or raise ImportRejected if the password is wrong."""
    user_key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), h.user_salt, h.rounds, 32)
    try:
        blob = _aes_cbc_decrypt(user_key, h.user_iv, h.master_blob)
        i = 0
        parts = []
        for _ in range(3):
            n = blob[i]
            parts.append(blob[i + 1:i + 1 + n])
            i += 1 + n
        master_iv, master_key, checksum = parts
    except (ValueError, IndexError):
        raise ImportRejected("Wrong backup password (master key could not be decrypted).")
    calc = hashlib.pbkdf2_hmac("sha1", mangle_key(master_key, h.version), h.checksum_salt, h.rounds, 32)
    if len(master_key) != 32 or len(master_iv) != 16 or not hmac.compare_digest(calc, checksum):
        raise ImportRejected("Wrong backup password (master key checksum mismatch).")
    return master_key, master_iv


class _ZlibReader(io.RawIOBase):
    def __init__(self, f):
        self.f = f
        self.d = zlib.decompressobj()
        self.buf = b""
        self.eof = False

    def readable(self):
        return True

    def readinto(self, b):
        while len(self.buf) < len(b) and not self.eof:
            chunk = self.f.read(65536)
            if not chunk:
                self.buf += self.d.flush()
                self.eof = True
                break
            self.buf += self.d.decompress(chunk)
        n = min(len(b), len(self.buf))
        b[:n] = self.buf[:n]
        self.buf = self.buf[n:]
        return n


class _AesCbcReader(io.RawIOBase):
    """Streaming AES-256-CBC decryption with PKCS#7 removal at end of stream."""

    def __init__(self, f, key: bytes, iv: bytes):
        self.f = f
        self.dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        self.unpad = padding.PKCS7(128).unpadder()
        self.buf = b""
        self.eof = False

    def readable(self):
        return True

    def readinto(self, b):
        while len(self.buf) < len(b) and not self.eof:
            chunk = self.f.read(65536)
            try:
                if chunk:
                    self.buf += self.unpad.update(self.dec.update(chunk))
                else:
                    self.buf += self.unpad.update(self.dec.finalize()) + self.unpad.finalize()
                    self.eof = True
            except ValueError as exc:
                raise ImportRejected("Encrypted payload is corrupted (invalid padding).") from exc
        n = min(len(b), len(self.buf))
        b[:n] = self.buf[:n]
        self.buf = self.buf[n:]
        return n


class AndroidBackupPlugin(ImportPlugin):
    name = "android_backup"
    description = "Android adb backup (.ab): unencrypted, or AES-256 with the supplied backup password."
    container_type = "android_backup"

    def probe(self, src, detected):
        return detected == "android_backup"

    def precheck(self, src, detected, limits, password: str | None = None):
        res = PrecheckResult()
        try:
            h = read_header(src)
        except ImportRejected as exc:
            res.blocking.append(str(exc))
            return res
        res.structure = {"version": h.version, "compressed": h.compressed, "encryption": h.encryption}
        if h.encrypted:
            res.structure["pbkdf2_rounds"] = h.rounds
            if not password:
                res.blocking.append("Encrypted Android backup: supply the backup password (provided by the owner "
                                    "or under legal authority). No password guessing is performed.")
            else:
                try:
                    unlock_master_key(h, password)
                    res.warnings.append("Backup password verified (master key checksum OK). The password is not stored.")
                except ImportRejected as exc:
                    res.blocking.append(str(exc))
        return res

    def extract(self, src, workdir, limits, password: str | None = None):
        h = read_header(src)
        with open(src, "rb") as f:
            f.seek(h.offset)
            stream = f
            if h.encrypted:
                if not password:
                    raise ImportRejected("Encrypted Android backup: password required.")
                key, iv = unlock_master_key(h, password)
                stream = io.BufferedReader(_AesCbcReader(stream, key, iv))
            if h.compressed:
                stream = io.BufferedReader(_ZlibReader(stream))
            try:
                with tarfile.open(fileobj=stream, mode="r|") as tf:
                    stats = safe_extract_tar_stream(tf, workdir, limits, source_size=src.stat().st_size)
            except (tarfile.TarError, zlib.error) as exc:
                raise ImportRejected(f"Corrupted Android backup payload: {exc}") from exc
        info = {"platform": "android", "backup_version": str(h.version), "backup_encrypted": h.encrypted}
        warnings = list(stats.warnings)
        if h.encrypted:
            warnings.append("Backup decrypted with the password supplied by the investigator (not stored).")
        return ExtractionResult(self.container_type, [ExtractedFile(p, p) for p in stats.files], warnings, info)
