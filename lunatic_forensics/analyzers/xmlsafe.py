"""Hardened XML parsing for untrusted evidence files.

DTDs and entity declarations are refused (protection against entity
expansion "billion laughs" and external entity attacks). Forensic export
formats handled by this application never require a DTD.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..core.errors import ImportRejected


def check_no_dtd(path: Path, scan_bytes: int = 64 * 1024) -> None:
    with open(path, "rb") as f:
        head = f.read(scan_bytes).upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
        raise ImportRejected("XML with DTD/entity declarations refused for safety.")


def iterparse(path: Path, events=("end",)):
    check_no_dtd(path)
    parser = ET.XMLPullParser(events=events)
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            if b"<!DOCTYPE" in chunk.upper() or b"<!ENTITY" in chunk.upper():
                raise ImportRejected("XML with DTD/entity declarations refused for safety.")
            parser.feed(chunk)
            yield from parser.read_events()
    parser.close()
    yield from parser.read_events()


def parse_bytes(data: bytes) -> ET.Element:
    up = data.upper()
    if b"<!DOCTYPE" in up or b"<!ENTITY" in up:
        raise ImportRejected("XML with DTD/entity declarations refused for safety.")
    return ET.fromstring(data)


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
