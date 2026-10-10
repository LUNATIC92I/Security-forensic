"""Analyzer framework.

An *analyzer* recognises a source file by its **content** (SQLite schema,
magic bytes, document structure), never by file name alone, and yields
:class:`ArtifactRecord` objects. Every record keeps the original values
(``raw``) separate from derived values (``interpreted``), and carries a
reference to the exact source (file, table, row id).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from pydantic import BaseModel, Field

from ..core.timeutils import to_iso


class Category(str, Enum):
    CONTACT = "contact"
    MESSAGE = "message"
    CALL = "call"
    MEDIA = "media"
    DOCUMENT = "document"
    BROWSER = "browser"
    APP = "app"
    LOCATION = "location"
    CALENDAR = "calendar"
    NOTE = "note"
    LOG = "log"
    DEVICE = "device_info"
    RECOVERED = "recovered"


class ArtifactRecord(BaseModel):
    category: Category
    subtype: str = ""
    timestamp: datetime | None = None
    timestamp_raw: str | None = None
    timestamp_method: str | None = None
    summary: str = ""
    identifiers: list[str] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)
    conversation_id: str | None = None
    direction: str | None = None          # incoming | outgoing | missed | rejected | unknown
    latitude: float | None = None
    longitude: float | None = None
    location_kind: str | None = None      # recorded | estimated
    sha256: str | None = None
    mime: str | None = None
    source_table: str | None = None
    source_rowid: str | None = None
    is_recovered: bool = False
    confidence: float | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    interpreted: dict[str, Any] = Field(default_factory=dict)

    def content_hash(self) -> str:
        key = {
            "c": self.category.value,
            "t": to_iso(self.timestamp.replace(microsecond=0)) if self.timestamp else None,
            "i": sorted(self.identifiers),
            "d": self.direction,
            "body": self.interpreted.get("body") or self.interpreted.get("text") or self.interpreted.get("url"),
            "sha": self.sha256,
        }
        if self.category == Category.CONTACT:
            key["t"] = None
            key["n"] = sorted(n.lower() for n in self.names)
        return hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class FileContext:
    path: Path
    rel_path: str
    virtual_path: str
    detected_type: str
    size: int
    evidence_file_id: int | None = None
    default_cc: str = "33"
    default_tz: str = "UTC"
    sha256: str | None = None
    mtime: datetime | None = None
    _tables: set[str] | None = field(default=None, repr=False)
    _columns: dict[str, set[str]] = field(default_factory=dict, repr=False)

    @property
    def logical_path(self) -> str:
        return self.virtual_path or self.rel_path

    @property
    def name(self) -> str:
        return Path(self.logical_path).name

    @property
    def lower_path(self) -> str:
        return self.logical_path.lower()

    def connect(self) -> sqlite3.Connection:
        """Open the (working copy) SQLite database strictly read-only."""
        uri = f"file:{self.path.resolve().as_posix()}?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True)
        con.row_factory = sqlite3.Row
        return con

    def tables(self) -> set[str]:
        if self._tables is None:
            self._tables = set()
            if self.detected_type == "sqlite":
                try:
                    con = self.connect()
                    try:
                        self._tables = {r[0].lower() for r in con.execute(
                            "SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
                    finally:
                        con.close()
                except sqlite3.DatabaseError:
                    self._tables = set()
        return self._tables

    def columns(self, table: str) -> set[str]:
        table = table.lower()
        if table not in self._columns:
            cols: set[str] = set()
            if table in self.tables():
                con = self.connect()
                try:
                    cols = {r[1].lower() for r in con.execute(f'PRAGMA table_info("{table}")')}
                finally:
                    con.close()
            self._columns[table] = cols
        return self._columns[table]

    def has(self, table: str, *cols: str) -> bool:
        return table.lower() in self.tables() and set(c.lower() for c in cols) <= self.columns(table)

    def read_text(self, limit: int = 50 * 1024 * 1024) -> str:
        with open(self.path, "rb") as f:
            data = f.read(limit)
        for enc in ("utf-8-sig", "utf-16"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return data.decode("latin-1")


class Analyzer(ABC):
    name: str = "base"
    version: str = "1.0"
    categories: tuple[Category, ...] = ()
    description: str = ""
    sources: str = ""            # documented formats handled
    status: str = "stable"       # stable | partial | experimental
    fallback: bool = False       # only used when no specific analyzer matched the file

    @abstractmethod
    def matches(self, f: FileContext) -> bool: ...

    @abstractmethod
    def parse(self, f: FileContext) -> Iterator[ArtifactRecord]: ...


def row_dict(row: sqlite3.Row) -> dict:
    out = {}
    for k in row.keys():
        v = row[k]
        if isinstance(v, bytes):
            v = {"_blob_len": len(v), "_hex_prefix": v[:32].hex()}
        out[k] = v
    return out


def safe_cols(f: FileContext, table: str, wanted: list[str]) -> list[str]:
    """Return SELECT expressions for wanted columns, NULL for missing ones."""
    have = f.columns(table)
    return [c if c.lower() in have else f"NULL AS {c}" for c in wanted]
