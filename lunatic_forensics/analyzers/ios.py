"""iOS artefact analyzers (unencrypted backups or authorised exports).

Timestamps use Apple absolute time (seconds - or nanoseconds on newer
releases - since 2001-01-01 UTC); the decoder records which unit was used.
"""
from __future__ import annotations

import gzip
import zlib
from collections import defaultdict

from ..core.normalize import normalize_email, normalize_identifier, normalize_phone
from ..core.timeutils import from_mac_absolute
from .base import Analyzer, ArtifactRecord, Category, FileContext, row_dict, safe_cols


def _mac(v):
    if v in (None, 0, ""):
        return None, None
    return from_mac_absolute(v)


def decode_attributed_body(blob: bytes | None) -> str | None:
    """Best-effort extraction of the plain string from an NSAttributedString
    typedstream (``message.attributedBody``, iOS 16+). Heuristic, documented
    by the forensic community; flagged as such in interpreted values."""
    if not blob or b"NSString" not in blob:
        return None
    try:
        rest = blob.split(b"NSString", 1)[1]
        rest = rest[5:]  # class info bytes preceding the length prefix
        if not rest:
            return None
        if rest[0] == 0x81:
            length = int.from_bytes(rest[1:3], "little")
            data = rest[3:3 + length]
        else:
            length = rest[0]
            data = rest[1:1 + length]
        return data.decode("utf-8", errors="replace")
    except (IndexError, ValueError):
        return None


class IosSmsAnalyzer(Analyzer):
    name = "ios.sms"
    version = "1.1"
    categories = (Category.MESSAGE,)
    description = "SMS / iMessage / RCS from iOS sms.db (HomeDomain/Library/SMS/sms.db)."
    sources = "sms.db: message, handle, chat, chat_message_join, attachment"

    def matches(self, f):
        return f.has("message", "rowid", "text", "handle_id", "date", "is_from_me") and f.has("handle", "rowid", "id")

    def parse(self, f):
        con = f.connect()
        try:
            handles = {r["ROWID"]: r["id"] for r in con.execute("SELECT ROWID, id FROM handle")}
            chats = {}
            if f.has("chat_message_join", "chat_id", "message_id") and f.has("chat", "rowid", "chat_identifier"):
                for r in con.execute("SELECT j.message_id, c.chat_identifier, c.ROWID AS cid FROM chat_message_join j "
                                     "JOIN chat c ON c.ROWID = j.chat_id"):
                    chats[r["message_id"]] = (r["chat_identifier"], r["cid"])
            atts = defaultdict(list)
            if f.has("message_attachment_join", "message_id", "attachment_id") and f.has("attachment", "rowid", "filename"):
                acols = ", ".join("a." + c if not c.startswith("NULL") else c for c in
                                  safe_cols(f, "attachment", ["filename", "mime_type", "transfer_name", "total_bytes"]))
                for r in con.execute(f"SELECT j.message_id, {acols} FROM message_attachment_join j "
                                     "JOIN attachment a ON a.ROWID = j.attachment_id"):
                    atts[r["message_id"]].append({"filename": r["filename"], "mime": r["mime_type"],
                                                  "name": r["transfer_name"], "bytes": r["total_bytes"]})
            cols = ", ".join(safe_cols(f, "message", ["ROWID", "guid", "text", "handle_id", "service", "date",
                                                      "date_read", "date_delivered", "is_from_me", "attributedBody",
                                                      "cache_has_attachments", "is_read"]))
            for r in con.execute(f"SELECT {cols} FROM message"):
                raw = row_dict(r)
                text = r["text"]
                text_source = "text"
                if not text:
                    decoded = decode_attributed_body(r["attributedBody"])
                    if decoded:
                        text, text_source = decoded, "attributedBody (heuristic decoding)"
                ts, method = _mac(r["date"])
                handle = handles.get(r["handle_id"])
                chat_id, cid = chats.get(r["ROWID"], (None, None))
                ident = normalize_identifier(handle, f.default_cc) if handle else None
                direction = "outgoing" if r["is_from_me"] else "incoming"
                service = r["service"] or "SMS"
                read_ts, _ = _mac(r["date_read"])
                yield ArtifactRecord(
                    category=Category.MESSAGE, subtype=service.lower(), timestamp=ts, timestamp_raw=str(r["date"]),
                    timestamp_method=method, identifiers=[ident] if ident else [], direction=direction,
                    conversation_id=f"ios-chat:{chat_id}" if chat_id else (f"ios-handle:{handle}" if handle else None),
                    summary=f"{service} {direction} {handle or '?'}: {(text or '')[:120]}",
                    source_table="message", source_rowid=str(r["ROWID"]), raw=raw,
                    interpreted={"body": text or "", "text_source": text_source, "service": service,
                                 "counterpart": ident, "attachments": atts.get(r["ROWID"], []),
                                 "read_at": read_ts.isoformat() if read_ts else None})
        finally:
            con.close()


class IosAddressBookAnalyzer(Analyzer):
    name = "ios.addressbook"
    version = "1.0"
    categories = (Category.CONTACT,)
    description = "Contacts from iOS AddressBook.sqlitedb."
    sources = "AddressBook.sqlitedb: ABPerson, ABMultiValue"

    def matches(self, f):
        return f.has("abperson", "rowid", "first", "last") and f.has("abmultivalue", "record_id", "property", "value")

    def parse(self, f):
        con = f.connect()
        try:
            mv = defaultdict(list)
            for r in con.execute("SELECT record_id, property, label, value FROM ABMultiValue" if
                                 "label" in f.columns("abmultivalue") else
                                 "SELECT record_id, property, NULL AS label, value FROM ABMultiValue"):
                mv[r["record_id"]].append(row_dict(r))
            cols = ", ".join(safe_cols(f, "abperson", ["ROWID", "First", "Last", "Middle", "Organization",
                                                       "Nickname", "Note", "CreationDate", "ModificationDate"]))
            for r in con.execute(f"SELECT {cols} FROM ABPerson"):
                name = " ".join(x for x in (r["First"], r["Middle"], r["Last"]) if x) or r["Organization"] or "(no name)"
                vals = mv.get(r["ROWID"], [])
                phones_raw = [v["value"] for v in vals if v["property"] == 3 and v["value"]]
                emails_raw = [v["value"] for v in vals if v["property"] == 4 and v["value"]]
                phones = [normalize_phone(p, f.default_cc) for p in phones_raw]
                emails = [normalize_email(e) for e in emails_raw]
                created, method = _mac(r["CreationDate"])
                yield ArtifactRecord(
                    category=Category.CONTACT, subtype="ios_contact", summary=f"{name} {' '.join(phones_raw)}".strip(),
                    identifiers=[i for i in phones + emails if i], names=[name], timestamp=None,
                    source_table="ABPerson", source_rowid=str(r["ROWID"]), raw={"person": row_dict(r), "multivalues": vals},
                    interpreted={"name": name, "phones": phones, "phones_raw": phones_raw, "emails": emails,
                                 "organization": r["Organization"],
                                 "created": created.isoformat() if created else None})
        finally:
            con.close()


class IosCallHistoryAnalyzer(Analyzer):
    name = "ios.callhistory"
    version = "1.0"
    categories = (Category.CALL,)
    description = "Calls (cellular, FaceTime, third-party CallKit) from iOS CallHistory.storedata."
    sources = "CallHistory.storedata: ZCALLRECORD"

    CALLTYPE = {1: "phone", 8: "facetime_video", 16: "facetime_audio"}

    def matches(self, f):
        return f.has("zcallrecord", "zaddress", "zdate", "zduration", "zoriginated")

    def parse(self, f):
        con = f.connect()
        try:
            cols = ", ".join(safe_cols(f, "zcallrecord", ["Z_PK", "ZADDRESS", "ZDATE", "ZDURATION", "ZORIGINATED",
                                                          "ZANSWERED", "ZCALLTYPE", "ZNAME", "ZSERVICE_PROVIDER",
                                                          "ZISO_COUNTRY_CODE", "ZLOCATION"]))
            for r in con.execute(f"SELECT {cols} FROM ZCALLRECORD"):
                addr = r["ZADDRESS"]
                if isinstance(addr, bytes):
                    addr = addr.decode("utf-8", errors="replace")
                ident = normalize_identifier(addr, f.default_cc) if addr else None
                if r["ZORIGINATED"]:
                    direction = "outgoing"
                else:
                    direction = "incoming" if r["ZANSWERED"] else "missed"
                ts, method = _mac(r["ZDATE"])
                kind = self.CALLTYPE.get(r["ZCALLTYPE"], f"type_{r['ZCALLTYPE']}")
                dur = round(float(r["ZDURATION"] or 0), 1)
                yield ArtifactRecord(
                    category=Category.CALL, subtype=kind, timestamp=ts, timestamp_raw=str(r["ZDATE"]),
                    timestamp_method=method, identifiers=[ident] if ident else [],
                    names=[r["ZNAME"]] if r["ZNAME"] else [], direction=direction,
                    summary=f"Call {direction} {addr or 'unknown'} ({dur}s, {kind})",
                    source_table="ZCALLRECORD", source_rowid=str(r["Z_PK"]), raw=row_dict(r),
                    interpreted={"counterpart": ident, "duration_s": dur, "call_type": kind,
                                 "service": r["ZSERVICE_PROVIDER"], "answered": bool(r["ZANSWERED"])})
        finally:
            con.close()


class IosCalendarAnalyzer(Analyzer):
    name = "ios.calendar"
    version = "1.0"
    categories = (Category.CALENDAR,)
    description = "Events from iOS Calendar.sqlitedb."
    sources = "Calendar.sqlitedb: CalendarItem, Location"

    def matches(self, f):
        return f.has("calendaritem", "summary", "start_date")

    def parse(self, f):
        con = f.connect()
        try:
            locs = {}
            if f.has("location", "rowid", "title"):
                locs = {r["ROWID"]: r["title"] for r in con.execute("SELECT ROWID, title FROM Location")}
            cols = ", ".join(safe_cols(f, "calendaritem", ["ROWID", "summary", "start_date", "end_date",
                                                           "location_id", "description", "start_tz"]))
            for r in con.execute(f"SELECT {cols} FROM CalendarItem"):
                ts, method = _mac(r["start_date"])
                end, _ = _mac(r["end_date"])
                loc = locs.get(r["location_id"])
                yield ArtifactRecord(
                    category=Category.CALENDAR, subtype="event", timestamp=ts, timestamp_raw=str(r["start_date"]),
                    timestamp_method=method, summary=f"Event: {r['summary'] or ''} @ {loc or ''}",
                    source_table="CalendarItem", source_rowid=str(r["ROWID"]), raw=row_dict(r),
                    interpreted={"title": r["summary"], "location": loc, "text": r["description"],
                                 "end": end.isoformat() if end else None, "event_timezone": r["start_tz"]})
        finally:
            con.close()


# ------------------------------------------------------------------ Notes
def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def protobuf_field(buf: bytes, field_no: int) -> bytes | None:
    """Return the first length-delimited field ``field_no`` of a protobuf message."""
    i = 0
    while i < len(buf):
        key, i = _varint(buf, i)
        fno, wt = key >> 3, key & 7
        if wt == 0:
            _, i = _varint(buf, i)
        elif wt == 1:
            i += 8
        elif wt == 5:
            i += 4
        elif wt == 2:
            ln, i = _varint(buf, i)
            if fno == field_no:
                return buf[i:i + ln]
            i += ln
        else:
            raise ValueError("unsupported wire type")
    return None


def decode_notestore_text(data: bytes | None) -> str | None:
    """Extract the plain text of a modern Apple Notes body.

    ZICNOTEDATA.ZDATA = gzip(NoteStoreProto{2: Document{3: Note{2: note_text}}}).
    Formatting, tables and attachments are not reconstructed.
    """
    if not data:
        return None
    try:
        raw = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else zlib.decompress(data)
        doc = protobuf_field(raw, 2)
        note = protobuf_field(doc, 3) if doc else None
        text = protobuf_field(note, 2) if note else None
        return text.decode("utf-8", errors="replace") if text is not None else None
    except (OSError, ValueError, zlib.error, EOFError):
        return None


class IosNotesAnalyzer(Analyzer):
    name = "ios.notes"
    version = "1.0"
    categories = (Category.NOTE,)
    description = "Apple Notes: NoteStore.sqlite (text only) and legacy notes.sqlite."
    sources = "NoteStore.sqlite: ZICCLOUDSYNCINGOBJECT + ZICNOTEDATA; notes.sqlite: ZNOTE + ZNOTEBODY"
    status = "partial"

    def matches(self, f):
        return f.has("zicnotedata", "znote", "zdata") and "ziccloudsyncingobject" in f.tables() or \
            f.has("znote", "z_pk", "ztitle") and f.has("znotebody", "zowner", "zcontent")

    def parse(self, f):
        con = f.connect()
        try:
            if "zicnotedata" in f.tables():
                cols = f.columns("ziccloudsyncingobject")
                title = "o.ZTITLE1" if "ztitle1" in cols else "NULL"
                created = next((f"o.{c.upper()}" for c in ("zcreationdate3", "zcreationdate1", "zcreationdate") if c in cols), "NULL")
                modified = next((f"o.{c.upper()}" for c in ("zmodificationdate1", "zmodificationdate") if c in cols), "NULL")
                locked = "o.ZISPASSWORDPROTECTED" if "zispasswordprotected" in cols else "0"
                q = (f"SELECT n.Z_PK AS pk, n.ZDATA AS data, {title} AS title, {created} AS created, "
                     f"{modified} AS modified, {locked} AS locked FROM ZICNOTEDATA n "
                     f"LEFT JOIN ZICCLOUDSYNCINGOBJECT o ON o.Z_PK = n.ZNOTE")
                for r in con.execute(q):
                    ts, method = _mac(r["modified"] or r["created"])
                    if r["locked"]:
                        text, note = None, "password-protected note: content not decrypted"
                    else:
                        text = decode_notestore_text(r["data"])
                        note = "text decoded from protobuf (formatting/attachments not reconstructed)" if text \
                            else "body could not be decoded"
                    yield ArtifactRecord(category=Category.NOTE, subtype="apple_note", timestamp=ts,
                                         timestamp_raw=str(r["modified"] or r["created"]), timestamp_method=method,
                                         summary=f"Note: {r['title'] or (text or '')[:60]}", source_table="ZICNOTEDATA",
                                         source_rowid=str(r["pk"]),
                                         raw={"title": r["title"], "created": r["created"], "modified": r["modified"],
                                              "data_len": len(r["data"] or b"")},
                                         interpreted={"title": r["title"], "text": text, "decoding": note,
                                                      "password_protected": bool(r["locked"])})
            else:
                for r in con.execute("SELECT n.Z_PK AS pk, n.ZTITLE AS title, n.ZCREATIONDATE AS created, "
                                     "n.ZMODIFICATIONDATE AS modified, b.ZCONTENT AS content FROM ZNOTE n "
                                     "LEFT JOIN ZNOTEBODY b ON b.ZOWNER = n.Z_PK"):
                    ts, method = _mac(r["modified"] or r["created"])
                    import re as _re
                    text = _re.sub(r"<[^>]+>", " ", r["content"] or "").strip()
                    yield ArtifactRecord(category=Category.NOTE, subtype="apple_note_legacy", timestamp=ts,
                                         timestamp_raw=str(r["modified"]), timestamp_method=method,
                                         summary=f"Note: {r['title'] or ''}", source_table="ZNOTE",
                                         source_rowid=str(r["pk"]), raw=row_dict(r),
                                         interpreted={"title": r["title"], "text": text})
        finally:
            con.close()


class IosPhotosDbAnalyzer(Analyzer):
    name = "ios.photos_db"
    version = "1.0"
    categories = (Category.LOCATION, Category.MEDIA)
    description = "Asset records and stored GPS coordinates from iOS Photos.sqlite."
    sources = "Photos.sqlite: ZASSET (ZGENERICASSET on older iOS)"

    def _table(self, f):
        for t in ("zasset", "zgenericasset"):
            if f.has(t, "zdirectory", "zfilename", "zdatecreated"):
                return t
        return None

    def matches(self, f):
        return self._table(f) is not None

    def parse(self, f):
        t = self._table(f)
        con = f.connect()
        try:
            cols = ", ".join(safe_cols(f, t, ["Z_PK", "ZDIRECTORY", "ZFILENAME", "ZDATECREATED", "ZLATITUDE",
                                              "ZLONGITUDE", "ZTRASHEDSTATE", "ZKIND"]))
            for r in con.execute(f"SELECT {cols} FROM {t.upper()}"):
                ts, method = _mac(r["ZDATECREATED"])
                lat, lon = r["ZLATITUDE"], r["ZLONGITUDE"]
                has_gps = lat not in (None, -180.0) and lon not in (None, -180.0) and not (lat == 0 and lon == 0)
                path = f"{r['ZDIRECTORY']}/{r['ZFILENAME']}"
                yield ArtifactRecord(
                    category=Category.LOCATION if has_gps else Category.MEDIA, subtype="photos_asset",
                    timestamp=ts, timestamp_raw=str(r["ZDATECREATED"]), timestamp_method=method,
                    latitude=lat if has_gps else None, longitude=lon if has_gps else None,
                    location_kind="recorded" if has_gps else None,
                    summary=f"Photos asset {path}" + (f" @ {lat:.5f},{lon:.5f}" if has_gps else ""),
                    source_table=t.upper(), source_rowid=str(r["Z_PK"]), raw=row_dict(r),
                    interpreted={"asset_path": path, "trashed": bool(r["ZTRASHEDSTATE"]),
                                 "location_note": "coordinates stored in Photos library metadata" if has_gps else None})
        finally:
            con.close()


ANALYZERS = [IosSmsAnalyzer(), IosAddressBookAnalyzer(), IosCallHistoryAnalyzer(), IosCalendarAnalyzer(),
             IosNotesAnalyzer(), IosPhotosDbAnalyzer()]
