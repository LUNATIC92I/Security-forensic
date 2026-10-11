"""Pre-import safety: real type detection and hardened archive extraction.

Protections implemented:

* magic-byte type detection (extension is never trusted) and mismatch alerts
* path traversal (``..``, absolute paths, drive letters, NUL bytes) -> reject
* symbolic / hard links, device nodes -> skipped and reported
* decompression bombs: per-member ratio, total size, file count limits and
  *streamed* byte counting (archive headers can lie about sizes)
* nested archives are not expanded automatically (they are inventoried)
"""
from __future__ import annotations

import os
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from ..core.config import ImportLimits
from ..core.errors import ImportRejected

CHUNK = 1024 * 1024

SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"SQLite format 3\x00", 0, "sqlite"),
    (b"\x37\x7f\x06\x82", 0, "sqlite_wal"),
    (b"\x37\x7f\x06\x83", 0, "sqlite_wal"),
    (b"PK\x03\x04", 0, "zip"),
    (b"PK\x05\x06", 0, "zip"),
    (b"\x1f\x8b", 0, "gzip"),
    (b"BZh", 0, "bzip2"),
    (b"\xfd7zXZ\x00", 0, "xz"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"ANDROID BACKUP\n", 0, "android_backup"),
    (b"\xff\xd8\xff", 0, "jpeg"),
    (b"\x89PNG\r\n\x1a\n", 0, "png"),
    (b"GIF87a", 0, "gif"),
    (b"GIF89a", 0, "gif"),
    (b"BM", 0, "bmp"),
    (b"%PDF-", 0, "pdf"),
    (b"bplist00", 0, "plist_binary"),
    (b"MZ", 0, "pe_executable"),
    (b"\x7fELF", 0, "elf_executable"),
    (b"\xcf\xfa\xed\xfe", 0, "macho_executable"),
    (b"\xca\xfe\xba\xbe", 0, "macho_executable"),
    (b"dex\n", 0, "dex"),
    (b"OggS", 0, "ogg"),
    (b"ID3", 0, "mp3"),
    (b"RIFF", 0, "riff"),
    (b"BEGIN:VCARD", 0, "vcard"),
    (b"BEGIN:VCALENDAR", 0, "icalendar"),
]

EXECUTABLE_TYPES = {"pe_executable", "elf_executable", "macho_executable", "dex", "script"}
ARCHIVE_TYPES = {"zip", "tar", "gzip", "bzip2", "xz", "7z", "rar", "android_backup"}

EXTENSION_EXPECTATIONS = {
    ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".png": {"png"}, ".gif": {"gif"}, ".pdf": {"pdf"},
    ".zip": {"zip"}, ".db": {"sqlite"}, ".sqlite": {"sqlite"}, ".sqlitedb": {"sqlite"},
    ".mp4": {"mp4", "mov"}, ".mov": {"mov", "mp4"}, ".heic": {"heic"}, ".ab": {"android_backup"},
    ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"}, ".odt": {"zip"}, ".apk": {"zip"},
    ".json": {"json"}, ".xml": {"xml"}, ".csv": {"text", "csv"}, ".txt": {"text"},
    ".vcf": {"vcard"}, ".ics": {"icalendar"}, ".tar": {"tar"}, ".gz": {"gzip"}, ".tgz": {"gzip"},
}


def detect_type(path: Path) -> str:
    path = Path(path)
    if path.is_dir():
        return "directory"
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return "unreadable"
    if not head:
        return "empty"
    for sig, off, name in SIGNATURES:
        if head[off:off + len(sig)] == sig:
            if name == "riff":
                return {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}.get(head[8:12], "riff")
            return name
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"hevc"):
            return "heic"
        if brand == b"qt  ":
            return "mov"
        return "mp4"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"#!"):
        return "script"
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = head.decode("utf-16")
            if not text.isprintable() and "\n" not in text:
                return "binary"
        except UnicodeDecodeError:
            return "binary"
    stripped = text.lstrip("﻿ \t\r\n")
    if stripped.startswith("<?xml") or stripped.startswith("<"):
        if "<plist" in stripped[:400]:
            return "plist_xml"
        return "xml"
    if stripped[:1] == "{" or stripped[:1] == "[" and stripped[1:].lstrip()[:1] in ('{', '[', '"', ']') or \
            stripped[:1] == "[" and re.match(r"\[\s*-?\d", stripped):
        return "json"
    if "\x00" in text:
        return "binary"
    first = stripped.split("\n", 1)[0]
    if first.count(",") >= 2 or first.count(";") >= 2 or first.count("\t") >= 2:
        return "csv"
    return "text"


def extension_mismatch(path: Path, detected: str) -> bool:
    exp = EXTENSION_EXPECTATIONS.get(Path(path).suffix.lower())
    if not exp or detected in ("empty", "unreadable"):
        return False
    if detected == "csv" and "text" in exp or detected == "text" and "csv" in exp:
        return False
    return detected not in exp


_DRIVE_RE = re.compile(r"^[a-zA-Z]:")
_INVALID_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')


def sanitize_member_path(name: str, limits: ImportLimits) -> PurePosixPath:
    """Validate an archive member name and return a safe relative path.

    Raises ImportRejected on traversal attempts.
    """
    if "\x00" in name:
        raise ImportRejected(f"Archive member contains a NUL byte: {name!r}")
    n = name.replace("\\", "/")
    if n.startswith("/") or _DRIVE_RE.match(n):
        raise ImportRejected(f"Absolute path in archive member: {name!r}")
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ImportRejected(f"Path traversal attempt in archive member: {name!r}")
    if not parts:
        raise ImportRejected(f"Empty archive member name: {name!r}")
    if len(parts) > limits.max_path_depth:
        raise ImportRejected(f"Archive member nested too deeply: {name!r}")
    clean = [(_INVALID_CHARS.sub("_", p)[:200] or "_") for p in parts]
    return PurePosixPath(*clean)


def _safe_target(dest: Path, rel: PurePosixPath) -> Path:
    """``dest`` must already be resolved (see callers) so that Windows 8.3 short
    names and long names compare equal."""
    target = (dest / Path(*rel.parts)).resolve()
    if os.path.commonpath([str(dest), str(target)]) != str(dest):
        raise ImportRejected(f"Archive member escapes extraction directory: {rel}")
    return target


def _unique(target: Path) -> Path:
    if not target.exists():
        return target
    i = 1
    while True:
        cand = target.with_name(f"{target.stem}__dup{i}{target.suffix}")
        if not cand.exists():
            return cand
        i += 1


@dataclass
class ExtractStats:
    files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    total_bytes: int = 0


def _copy_stream(src, out, limits: ImportLimits, stats: ExtractStats, declared: int | None, name: str) -> int:
    copied = 0
    while True:
        chunk = src.read(CHUNK)
        if not chunk:
            break
        copied += len(chunk)
        stats.total_bytes += len(chunk)
        if copied > limits.max_member_bytes:
            raise ImportRejected(f"Archive member exceeds per-file limit: {name}")
        if declared is not None and copied > declared:
            raise ImportRejected(f"Archive member larger than declared (possible bomb): {name}")
        if stats.total_bytes > limits.max_total_uncompressed:
            raise ImportRejected("Total extracted size exceeds limit (possible decompression bomb).")
        out.write(chunk)
    return copied


def zip_risks(src: Path, limits: ImportLimits) -> tuple[list[str], list[str]]:
    """Static inspection of a ZIP central directory -> (blocking, warnings)."""
    blocking, warnings = [], []
    try:
        with zipfile.ZipFile(src) as zf:
            infos = zf.infolist()
    except zipfile.BadZipFile as exc:
        return [f"Corrupted ZIP archive: {exc}"], []
    if len(infos) > limits.max_files:
        blocking.append(f"Too many entries ({len(infos)} > {limits.max_files}).")
    total = 0
    for info in infos:
        try:
            sanitize_member_path(info.filename, limits)
        except ImportRejected as exc:
            blocking.append(str(exc))
            continue
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            warnings.append(f"Symbolic link will be skipped: {info.filename}")
        if info.flag_bits & 0x1:
            warnings.append(f"Encrypted member cannot be extracted: {info.filename}")
        total += info.file_size
        if info.compress_size > 0 and info.file_size / info.compress_size > limits.max_compression_ratio:
            blocking.append(f"Suspicious compression ratio for {info.filename} (possible bomb).")
        elif info.compress_size == 0 and info.file_size > 0:
            blocking.append(f"Inconsistent sizes for {info.filename}.")
        if info.file_size > limits.max_member_bytes:
            blocking.append(f"Member too large: {info.filename}")
    if total > limits.max_total_uncompressed:
        blocking.append("Declared uncompressed size exceeds limit.")
    return blocking[:50], warnings[:200]


def safe_extract_zip(src: Path, dest: Path, limits: ImportLimits) -> ExtractStats:
    blocking, warnings = zip_risks(src, limits)
    if blocking:
        raise ImportRejected("ZIP archive rejected by safety checks.", blocking)
    stats = ExtractStats(warnings=list(warnings))
    dest.mkdir(parents=True, exist_ok=True)
    dest = dest.resolve()
    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode) or info.flag_bits & 0x1:
                continue
            rel = sanitize_member_path(info.filename, limits)
            target = _unique(_safe_target(dest, rel))
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as fsrc, open(target, "wb") as out:
                _copy_stream(fsrc, out, limits, stats, info.file_size, info.filename)
            try:
                import time
                ts = time.mktime(info.date_time + (0, 0, -1))
                os.utime(target, (ts, ts))
            except (OverflowError, ValueError, OSError):
                pass
            stats.files.append(target.relative_to(dest).as_posix())
            if len(stats.files) > limits.max_files:
                raise ImportRejected("Too many files extracted.")
    return stats


def safe_extract_tar_stream(tf: tarfile.TarFile, dest: Path, limits: ImportLimits,
                            source_size: int | None = None) -> ExtractStats:
    """Extract an opened tar (can be in streaming mode) safely."""
    stats = ExtractStats()
    dest.mkdir(parents=True, exist_ok=True)
    dest = dest.resolve()
    count = 0
    for member in tf:
        count += 1
        if count > limits.max_files:
            raise ImportRejected("Too many entries in TAR archive.")
        rel = sanitize_member_path(member.name, limits)
        if member.isdir():
            continue
        if member.issym() or member.islnk():
            stats.warnings.append(f"Link skipped: {member.name}")
            continue
        if not member.isfile():
            stats.warnings.append(f"Special file skipped: {member.name}")
            continue
        target = _unique(_safe_target(dest, rel))
        target.parent.mkdir(parents=True, exist_ok=True)
        fsrc = tf.extractfile(member)
        if fsrc is None:
            continue
        with open(target, "wb") as out:
            _copy_stream(fsrc, out, limits, stats, member.size, member.name)
        try:
            os.utime(target, (member.mtime, member.mtime))
        except (OverflowError, ValueError, OSError):
            pass
        stats.files.append(target.relative_to(dest).as_posix())
        if source_size and source_size > 0 and stats.total_bytes > 1024 * 1024 and \
                stats.total_bytes / source_size > limits.max_compression_ratio:
            raise ImportRejected("Overall compression ratio exceeds limit (possible decompression bomb).")
    return stats


def safe_extract_tar(src: Path, dest: Path, limits: ImportLimits) -> ExtractStats:
    try:
        with tarfile.open(src, "r|*") as tf:
            return safe_extract_tar_stream(tf, dest, limits, source_size=src.stat().st_size)
    except tarfile.TarError as exc:
        raise ImportRejected(f"Corrupted TAR archive: {exc}") from exc


def is_tar(path: Path) -> bool:
    try:
        return tarfile.is_tarfile(path)
    except (OSError, tarfile.TarError):
        return False
