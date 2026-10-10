"""Cryptographic hashing helpers for evidence integrity."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

CHUNK = 1024 * 1024


def hash_file(path: Path | str, with_md5: bool = True) -> tuple[str, str, int]:
    """Return (sha256, md5, size). MD5 is kept for interoperability only."""
    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False) if with_md5 else None
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            sha.update(chunk)
            if md5:
                md5.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), (md5.hexdigest() if md5 else ""), size


def sha256_file(path: Path | str) -> str:
    return hash_file(path, with_md5=False)[0]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iter_regular_files(root: Path):
    """Yield regular files under root (sorted, symlinks are never followed)."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            yield p


def hash_directory(root: Path) -> tuple[str, list[tuple[str, str, int]], int]:
    """Deterministic manifest hash of a directory.

    The manifest is the sorted list of ``<sha256>  <size>  <relative posix path>``
    lines; its SHA-256 identifies the directory content.
    Returns (manifest_sha256, entries, total_size).
    """
    root = Path(root)
    entries = []
    total = 0
    for p in iter_regular_files(root):
        sha, _, size = hash_file(p, with_md5=False)
        rel = p.relative_to(root).as_posix()
        entries.append((rel, sha, size))
        total += size
    entries.sort()
    manifest = "\n".join(f"{sha}  {size}  {rel}" for rel, sha, size in entries)
    return sha256_bytes(manifest.encode("utf-8")), entries, total
