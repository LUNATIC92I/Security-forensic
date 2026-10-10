"""EXPERIMENTAL residual data analysis.

A deleted record or file can only be recovered **if the corresponding bytes
still exist in the source**. Results are fragments: they are flagged
``is_recovered=True`` with a low confidence score and an exact byte offset so
an examiner can verify them manually with a hex viewer.

* SQLite: strings found in free-list pages, unallocated areas and freeblocks
  of table b-tree leaf pages, and in WAL frames.
* Raw images (``.img``, ``.dd``, ``.raw``, ``.bin``): signature-based carving
  of JPEG, PNG and PDF (header/footer, size-capped).
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

from ..core.hashing import sha256_bytes
from .base import Analyzer, ArtifactRecord, Category

STRING_RE = re.compile(rb"[\x20-\x7e\xc2-\xf4][\x20-\x7e\x80-\xbf\xc2-\xf4]{7,}")
MAX_DB = 512 * 1024 * 1024
MAX_FRAGMENTS = 5000


def _strings(region: bytes, base_offset: int):
    for m in STRING_RE.finditer(region):
        try:
            s = m.group(0).decode("utf-8")
        except UnicodeDecodeError:
            continue
        if sum(c.isalnum() for c in s) / len(s) < 0.5:
            continue
        yield base_offset + m.start(), s


def sqlite_residual_regions(data: bytes) -> list[tuple[str, int, int, int]]:
    """Return (kind, page_no, start, end) regions that may hold residual data."""
    if len(data) < 100 or not data.startswith(b"SQLite format 3\x00"):
        return []
    page_size = struct.unpack(">H", data[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size & (page_size - 1):
        return []
    n_pages = len(data) // page_size
    regions = []
    free_pages = set()
    trunk = struct.unpack(">I", data[32:36])[0]
    seen = set()
    while 0 < trunk <= n_pages and trunk not in seen:
        seen.add(trunk)
        off = (trunk - 1) * page_size
        free_pages.add(trunk)
        nxt, count = struct.unpack(">II", data[off:off + 8])
        for k in range(min(count, (page_size - 8) // 4)):
            leaf = struct.unpack(">I", data[off + 8 + 4 * k: off + 12 + 4 * k])[0]
            if 0 < leaf <= n_pages:
                free_pages.add(leaf)
        trunk = nxt
    for p in sorted(free_pages):
        regions.append(("freelist_page", p, (p - 1) * page_size, p * page_size))
    for p in range(1, n_pages + 1):
        if p in free_pages:
            continue
        off = (p - 1) * page_size
        hdr = off + (100 if p == 1 else 0)
        if data[hdr] != 0x0D:  # table b-tree leaf
            continue
        first_fb, ncells, content_start, _frag = struct.unpack(">HHHB", data[hdr + 1:hdr + 8])
        content_start = 65536 if content_start == 0 else content_start
        un_start = hdr + 8 + 2 * ncells
        un_end = off + content_start
        if un_end - un_start > 8:
            regions.append(("unallocated", p, un_start, un_end))
        fb = first_fb
        hops = 0
        while fb and hops < 1000:
            hops += 1
            a = off + fb
            if a + 4 > off + page_size:
                break
            nxt, size = struct.unpack(">HH", data[a:a + 4])
            if size >= 4:
                regions.append(("freeblock", p, a + 4, min(a + size, off + page_size)))
            fb = nxt
    return regions


class SqliteResidualAnalyzer(Analyzer):
    name = "recovery.sqlite_residual"
    version = "0.1"
    categories = (Category.RECOVERED,)
    description = "EXPERIMENTAL: text fragments in SQLite free pages / unallocated space / freeblocks / WAL."
    sources = "any SQLite database or -wal file"
    status = "experimental"

    def matches(self, f):
        return f.detected_type in ("sqlite", "sqlite_wal") and 0 < f.size <= MAX_DB

    def parse(self, f):
        data = f.path.read_bytes()
        n = 0
        if f.detected_type == "sqlite_wal":
            regions = [("wal_frames", 0, 32, len(data))]
        else:
            regions = sqlite_residual_regions(data)
        for kind, page, start, end in regions:
            for off, s in _strings(data[start:end], start):
                n += 1
                if n > MAX_FRAGMENTS:
                    return
                yield ArtifactRecord(
                    category=Category.RECOVERED, subtype=f"sqlite_{kind}", is_recovered=True, confidence=0.3,
                    summary=f"[residual {kind} p{page} @0x{off:x}] {s[:200]}", source_table=kind,
                    source_rowid=f"page{page}@{off}",
                    raw={"offset": off, "page": page, "region": [start, end], "hex": data[off:off + min(len(s.encode()), 256)].hex()},
                    interpreted={"text": s, "warning": "Fragment of residual data; original record, table and time "
                                                       "are unknown. Verify manually at the given offset."})


CARVE_SIGS = [
    ("jpeg", b"\xff\xd8\xff", b"\xff\xd9", 20 * 1024 * 1024),
    ("png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 20 * 1024 * 1024),
    ("pdf", b"%PDF-", b"%%EOF", 50 * 1024 * 1024),
]
RAW_SUFFIXES = (".img", ".dd", ".raw", ".bin", ".001", ".dmp")


class FileCarvingAnalyzer(Analyzer):
    name = "recovery.file_carving"
    version = "0.1"
    categories = (Category.RECOVERED,)
    description = "EXPERIMENTAL: signature-based carving (JPEG, PNG, PDF) in raw disk/partition images."
    sources = ".img, .dd, .raw, .bin, .001, .dmp"
    status = "experimental"
    MAX_CARVED = 2000

    def matches(self, f):
        return f.name.lower().endswith(RAW_SUFFIXES) and f.size > 0

    def parse(self, f):
        import mmap
        out_dir = getattr(f, "derived_dir", None)
        n = 0
        with open(f.path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            size = len(mm)
            for kind, head, foot, maxlen in CARVE_SIGS:
                pos = mm.find(head)
                while pos != -1:
                    end = mm.find(foot, pos + len(head), min(pos + maxlen, size))
                    if end == -1:
                        pos = mm.find(head, pos + 1)
                        continue
                    data = mm[pos:end + len(foot)]
                    n += 1
                    sha = sha256_bytes(data)
                    carved_path = None
                    if out_dir is not None:
                        Path(out_dir).mkdir(parents=True, exist_ok=True)
                        carved_path = Path(out_dir) / f"carved_{pos:012x}.{kind}"
                        carved_path.write_bytes(data)
                    yield ArtifactRecord(
                        category=Category.RECOVERED, subtype=f"carved_{kind}", is_recovered=True,
                        confidence=0.5, sha256=sha, mime=kind,
                        summary=f"[carved {kind} @0x{pos:x}, {len(data)} bytes]",
                        source_table="raw_offset", source_rowid=str(pos),
                        raw={"offset": pos, "length": len(data)},
                        interpreted={"carved_path": str(carved_path) if carved_path else None,
                                     "warning": "Carved by header/footer signature: the file may be fragmented, "
                                                "truncated (e.g. JPEG ending at an embedded thumbnail) or belong "
                                                "to allocated space. Validate manually."})
                    if n >= self.MAX_CARVED:
                        return
                    pos = mm.find(head, end + len(foot))


ANALYZERS = [SqliteResidualAnalyzer(), FileCarvingAnalyzer()]
