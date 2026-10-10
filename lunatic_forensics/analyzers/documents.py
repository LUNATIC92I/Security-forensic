"""Documents: identification, hashes, metadata and text indexing.

* OOXML (docx/xlsx/pptx) and ODF: core properties + text (size-limited, zip-bomb guarded)
* PDF: Info dictionary (uncompressed objects only) - text extraction not available
  without an external PDF library; reported as a limitation
* Plain text / CSV / JSON / XML not handled by a specific parser: text indexing (fallback)
"""
from __future__ import annotations

import re
import zipfile

from ..core.timeutils import parse_datetime
from .base import Analyzer, ArtifactRecord, Category
from .xmlsafe import local, parse_bytes

MAX_MEMBER = 50 * 1024 * 1024
MAX_TEXT = 256 * 1024
OOXML = {".docx": "word", ".xlsx": "spreadsheet", ".pptx": "presentation"}
ODF = {".odt": "text", ".ods": "spreadsheet", ".odp": "presentation"}


def _read_member(zf: zipfile.ZipFile, name: str) -> bytes | None:
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_MEMBER or (info.compress_size and info.file_size / info.compress_size > 200):
        return None
    with zf.open(info) as fh:
        return fh.read(MAX_MEMBER + 1)[:MAX_MEMBER]


def _pdf_date(v: str | None):
    if not v:
        return None, None
    m = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+\-])?(\d{2})?'?(\d{2})?", v)
    if not m:
        return None, None
    y, mo, d, h, mi, s, sign, oh, om = m.groups()
    iso = f"{y}-{mo or '01'}-{d or '01'}T{h or '00'}:{mi or '00'}:{s or '00'}"
    if sign in ("+", "-") and oh:
        iso += f"{sign}{oh}:{om or '00'}"
    elif sign in ("Z", "z"):
        iso += "+00:00"
    return parse_datetime(iso)


def _pdf_string(data: bytes, key: bytes) -> str | None:
    m = re.search(rb"/" + key + rb"\s*\(((?:\\.|[^\\)])*)\)", data)
    if m:
        s = m.group(1)
        if s.startswith(b"\xfe\xff"):
            return s[2:].decode("utf-16-be", errors="replace")
        return re.sub(rb"\\(.)", rb"\1", s).decode("latin-1", errors="replace")
    m = re.search(rb"/" + key + rb"\s*<([0-9A-Fa-f\s]+)>", data)
    if m:
        try:
            b = bytes.fromhex(m.group(1).decode().replace(" ", ""))
            return b[2:].decode("utf-16-be", errors="replace") if b.startswith(b"\xfe\xff") else b.decode("latin-1")
        except ValueError:
            return None
    return None


class DocumentAnalyzer(Analyzer):
    name = "documents.metadata"
    version = "1.0"
    categories = (Category.DOCUMENT,)
    description = "Office (OOXML/ODF) and PDF documents: metadata, hashes, text indexing where possible."
    sources = "docx, xlsx, pptx, odt, ods, odp, pdf"

    def matches(self, f):
        suf = "." + f.name.rsplit(".", 1)[-1].lower() if "." in f.name else ""
        return f.detected_type == "pdf" or f.detected_type == "zip" and (suf in OOXML or suf in ODF)

    def parse(self, f):
        suf = "." + f.name.rsplit(".", 1)[-1].lower() if "." in f.name else ""
        meta, text, notes = {}, "", []
        try:
            if f.detected_type == "pdf":
                meta, notes = self._pdf(f)
                kind = "pdf"
            elif suf in OOXML:
                meta, text = self._ooxml(f, OOXML[suf])
                kind = suf[1:]
            else:
                meta, text = self._odf(f)
                kind = suf[1:]
        except (zipfile.BadZipFile, OSError, ValueError, Exception) as exc:  # noqa: BLE001 - untrusted input
            notes.append(f"Document could not be fully parsed: {type(exc).__name__}")
            kind = f.detected_type
        created = meta.get("created") or meta.get("creation_date")
        ts, method = parse_datetime(created) if created else (None, None)
        if f.detected_type == "pdf" and meta.get("_created_dt"):
            ts, method = meta.pop("_created_dt"), "pdf_date"
        meta.pop("_created_dt", None)
        yield ArtifactRecord(
            category=Category.DOCUMENT, subtype=kind, timestamp=ts, timestamp_raw=str(created) if created else None,
            timestamp_method=method, sha256=f.sha256, mime=kind,
            summary=f"{kind.upper()} {f.name} {meta.get('title') or ''} ({meta.get('creator') or meta.get('author') or 'unknown author'})",
            names=[n for n in (meta.get("creator"), meta.get("author"), meta.get("last_modified_by")) if n],
            raw={"metadata": meta}, interpreted={**meta, "text": text[:MAX_TEXT], "notes": notes,
                                                  "file_name": f.name, "path": f.logical_path})

    def _pdf(self, f):
        with open(f.path, "rb") as fh:
            head = fh.read(2 * 1024 * 1024)
            if f.size > 3 * 1024 * 1024:
                fh.seek(-1024 * 1024, 2)
            tail = fh.read()
        data = head + tail
        meta = {}
        for key, field in ((b"Title", "title"), (b"Author", "author"), (b"Creator", "creator_tool"),
                           (b"Producer", "producer"), (b"CreationDate", "creation_date"), (b"ModDate", "mod_date"),
                           (b"Subject", "subject")):
            v = _pdf_string(data, key)
            if v:
                meta[field] = v
        ver = re.match(rb"%PDF-(\d\.\d)", head)
        meta["pdf_version"] = ver.group(1).decode() if ver else None
        meta["encrypted"] = b"/Encrypt" in data
        meta["pages_estimate"] = len(re.findall(rb"/Type\s*/Page[^s]", head))
        dt, _ = _pdf_date(meta.get("creation_date"))
        if dt:
            meta["_created_dt"] = dt
        notes = ["PDF text extraction not available (no PDF text library bundled); metadata from uncompressed "
                 "Info dictionary only - XMP / object-stream metadata may be missed."]
        return meta, notes

    def _ooxml(self, f, kind):
        meta, texts = {}, []
        with zipfile.ZipFile(f.path) as zf:
            core = _read_member(zf, "docProps/core.xml")
            if core:
                for el in parse_bytes(core):
                    tag = local(el.tag)
                    if el.text:
                        meta[{"lastModifiedBy": "last_modified_by"}.get(tag, tag)] = el.text.strip()
            app = _read_member(zf, "docProps/app.xml")
            if app:
                for el in parse_bytes(app):
                    if local(el.tag) in ("Application", "Pages", "Company", "TotalTime") and el.text:
                        meta[local(el.tag).lower()] = el.text
            if kind == "word":
                names = ["word/document.xml"]
                tag = "t"
            elif kind == "spreadsheet":
                names = ["xl/sharedStrings.xml"]
                tag = "t"
            else:
                names = sorted(n for n in zf.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n))
                tag = "t"
            total = 0
            for n in names:
                data = _read_member(zf, n)
                if not data:
                    continue
                for el in parse_bytes(data).iter():
                    if local(el.tag) == tag and el.text:
                        texts.append(el.text)
                        total += len(el.text)
                        if total > MAX_TEXT:
                            break
        meta = {k: v for k, v in meta.items() if k in ("title", "creator", "last_modified_by", "created", "modified",
                                                       "subject", "description", "keywords", "application", "pages",
                                                       "company", "totaltime", "revision")}
        return meta, " ".join(texts)

    def _odf(self, f):
        meta, texts = {}, []
        with zipfile.ZipFile(f.path) as zf:
            m = _read_member(zf, "meta.xml")
            if m:
                for el in parse_bytes(m).iter():
                    tag = local(el.tag)
                    if el.text and tag in ("title", "initial-creator", "creator", "creation-date", "date", "generator"):
                        meta[{"initial-creator": "creator", "creator": "last_modified_by",
                              "creation-date": "created", "date": "modified", "generator": "application"}.get(tag, tag)] = el.text
            c = _read_member(zf, "content.xml")
            if c:
                for el in parse_bytes(c).iter():
                    if local(el.tag) in ("p", "h", "span") and el.text:
                        texts.append(el.text)
        return meta, " ".join(texts)[:MAX_TEXT]


class TextIndexAnalyzer(Analyzer):
    name = "documents.text_index"
    version = "1.0"
    categories = (Category.DOCUMENT,)
    description = "Fallback text indexing for text/CSV/JSON/XML files without a specific parser."
    sources = "any UTF-8/UTF-16 text file (first 256 KiB indexed)"
    fallback = True

    def matches(self, f):
        return f.detected_type in ("text", "csv", "json", "xml", "plist_xml")

    def parse(self, f):
        text = f.read_text(MAX_TEXT)
        yield ArtifactRecord(category=Category.DOCUMENT, subtype=f.detected_type, sha256=f.sha256, mime=f.detected_type,
                             summary=f"{f.detected_type.upper()} {f.name} ({f.size} bytes)",
                             raw={"size": f.size},
                             interpreted={"text": text, "file_name": f.name, "path": f.logical_path,
                                          "truncated": f.size > MAX_TEXT,
                                          "file_mtime": f.mtime.isoformat() if f.mtime else None})


ANALYZERS = [DocumentAnalyzer(), TextIndexAnalyzer()]
