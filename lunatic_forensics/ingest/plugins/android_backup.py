"""Android ``adb backup`` (.ab) container.

Format (AOSP ``BackupManagerService``): text header
``ANDROID BACKUP\\n<version>\\n<compressed 0|1>\\n<encryption>\\n`` followed by
a (zlib-deflated when compressed=1) TAR stream. Only unencrypted backups are
supported: password-protected backups (``AES-256``) are reported as
unsupported - no password guessing is performed.
"""
from __future__ import annotations

import io
import tarfile
import zlib
from pathlib import Path

from ...core.errors import ImportRejected
from ..safety import safe_extract_tar_stream
from .base import ExtractedFile, ExtractionResult, ImportPlugin, PrecheckResult


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


def read_header(path: Path) -> dict:
    with open(path, "rb") as f:
        lines = [f.readline() for _ in range(4)]
        offset = f.tell()
    try:
        magic, version, compressed, enc = (l.decode("ascii").strip() for l in lines)
    except UnicodeDecodeError as exc:
        raise ImportRejected("Malformed Android backup header.") from exc
    if magic != "ANDROID BACKUP":
        raise ImportRejected("Not an Android backup file.")
    return {"version": version, "compressed": compressed == "1", "encryption": enc, "offset": offset}


class AndroidBackupPlugin(ImportPlugin):
    name = "android_backup"
    description = "Android adb backup (.ab), unencrypted only."
    container_type = "android_backup"

    def probe(self, src, detected):
        return detected == "android_backup"

    def precheck(self, src, detected, limits):
        res = PrecheckResult()
        try:
            h = read_header(src)
        except ImportRejected as exc:
            res.blocking.append(str(exc))
            return res
        res.structure = {k: v for k, v in h.items() if k != "offset"}
        if h["encryption"].lower() != "none":
            res.blocking.append("Encrypted Android backup: decryption is not supported by this version "
                                "(supply an unencrypted backup produced with the owner's authorisation).")
        return res

    def extract(self, src, workdir, limits):
        h = read_header(src)
        if h["encryption"].lower() != "none":
            raise ImportRejected("Encrypted Android backups are not supported.")
        with open(src, "rb") as f:
            f.seek(h["offset"])
            stream = io.BufferedReader(_ZlibReader(f)) if h["compressed"] else f
            try:
                with tarfile.open(fileobj=stream, mode="r|") as tf:
                    stats = safe_extract_tar_stream(tf, workdir, limits, source_size=src.stat().st_size)
            except (tarfile.TarError, zlib.error) as exc:
                raise ImportRejected(f"Corrupted Android backup payload: {exc}") from exc
        return ExtractionResult(self.container_type, [ExtractedFile(p, p) for p in stats.files],
                                stats.warnings, {"platform": "android", "backup_version": h["version"]})
