"""Messaging application adapters.

Each adapter targets a *documented / community-documented* database schema
and declares the schema variants it supports. Only plaintext databases that
are present in the evidence are parsed: end-to-end encryption is never
circumvented, keys are never extracted and no remote account is accessed.
Encrypted stores (e.g. WhatsApp ``msgstore.db.crypt14/15``, Signal SQLCipher
database) are reported by the application inventory as *not parsable*.
"""
from __future__ import annotations

from collections import defaultdict

from ..core.normalize import normalize_identifier, normalize_phone
from ..core.timeutils import from_mac_absolute, from_unix_millis
from .base import Analyzer, ArtifactRecord, Category, row_dict, safe_cols
from .xmlsafe import iterparse


class WhatsAppAndroidAnalyzer(Analyzer):
    name = "messaging.whatsapp_android"
    version = "1.0"
    categories = (Category.MESSAGE,)
    description = "WhatsApp for Android decrypted msgstore.db (legacy 'messages' and current 'message' schemas)."
    sources = "msgstore.db: messages (legacy) | message, chat, jid, message_media, message_location"
    status = "partial"

    def _variant(self, f):
        if f.has("message", "chat_row_id", "from_me", "timestamp", "text_data") and f.has("jid", "_id", "raw_string"):
            return "modern"
        if f.has("messages", "key_remote_jid", "key_from_me", "data", "timestamp"):
            return "legacy"
        return None

    def matches(self, f):
        return self._variant(f) is not None

    def parse(self, f):
        con = f.connect()
        try:
            if self._variant(f) == "legacy":
                cols = ", ".join(safe_cols(f, "messages", ["_id", "key_remote_jid", "key_from_me", "key_id", "data",
                                                           "timestamp", "media_mime_type", "media_name", "latitude",
                                                           "longitude", "remote_resource", "status"]))
                for r in con.execute(f"SELECT {cols} FROM messages WHERE key_remote_jid IS NOT NULL"):
                    if r["key_remote_jid"] == "-1" or r["key_remote_jid"] == "status@broadcast" and not r["data"]:
                        continue
                    yield self._rec(f, r["_id"], r["key_remote_jid"], r["remote_resource"], r["key_from_me"],
                                    r["timestamp"], r["data"], r["media_mime_type"], r["media_name"],
                                    r["latitude"], r["longitude"], row_dict(r), "messages", "legacy")
            else:
                jids = {r["_id"]: r["raw_string"] for r in con.execute("SELECT _id, raw_string FROM jid")}
                chats = {}
                if f.has("chat", "_id", "jid_row_id"):
                    chats = {r["_id"]: jids.get(r["jid_row_id"]) for r in con.execute("SELECT _id, jid_row_id FROM chat")}
                media, locs = {}, {}
                if f.has("message_media", "message_row_id", "mime_type"):
                    for r in con.execute("SELECT message_row_id, mime_type, " +
                                         ("file_path" if "file_path" in f.columns("message_media") else "NULL") +
                                         " AS file_path FROM message_media"):
                        media[r["message_row_id"]] = (r["mime_type"], r["file_path"])
                if f.has("message_location", "message_row_id", "latitude", "longitude"):
                    for r in con.execute("SELECT message_row_id, latitude, longitude FROM message_location"):
                        locs[r["message_row_id"]] = (r["latitude"], r["longitude"])
                cols = ", ".join(safe_cols(f, "message", ["_id", "chat_row_id", "from_me", "key_id", "sender_jid_row_id",
                                                          "timestamp", "text_data", "message_type", "status"]))
                for r in con.execute(f"SELECT {cols} FROM message"):
                    chat_jid = chats.get(r["chat_row_id"])
                    if not chat_jid:
                        continue
                    mt, fp = media.get(r["_id"], (None, None))
                    lat, lon = locs.get(r["_id"], (None, None))
                    yield self._rec(f, r["_id"], chat_jid, jids.get(r["sender_jid_row_id"]), r["from_me"], r["timestamp"],
                                    r["text_data"], mt, fp, lat, lon, row_dict(r), "message", "modern")
        finally:
            con.close()

    def _rec(self, f, rowid, chat_jid, sender_jid, from_me, ts_raw, text, mime, media_name, lat, lon, raw, table, variant):
        is_group = str(chat_jid).endswith("@g.us")
        counterpart = sender_jid if is_group and sender_jid else chat_jid
        ident = normalize_identifier(counterpart, f.default_cc)
        direction = "outgoing" if from_me else "incoming"
        has_loc = lat not in (None, 0) and lon not in (None, 0)
        ids = [ident] if ident and (not is_group or not from_me) else []
        return ArtifactRecord(
            category=Category.MESSAGE, subtype="whatsapp", timestamp=from_unix_millis(ts_raw) if ts_raw else None,
            timestamp_raw=str(ts_raw), timestamp_method="unix_ms", identifiers=ids, direction=direction,
            conversation_id=f"whatsapp:{chat_jid}", latitude=lat if has_loc else None, longitude=lon if has_loc else None,
            location_kind="recorded" if has_loc else None,
            summary=f"WhatsApp {direction} {counterpart}: {(text or ('[' + mime + ']' if mime else ''))[:120]}",
            source_table=table, source_rowid=str(rowid), raw=raw,
            interpreted={"body": text or "", "chat": chat_jid, "group": is_group, "sender": sender_jid,
                         "media_mime": mime, "media": media_name, "schema_variant": variant,
                         "location_note": "location shared in message content" if has_loc else None})


class WhatsAppIosAnalyzer(Analyzer):
    name = "messaging.whatsapp_ios"
    version = "1.0"
    categories = (Category.MESSAGE,)
    description = "WhatsApp for iOS ChatStorage.sqlite."
    sources = "ChatStorage.sqlite: ZWAMESSAGE, ZWACHATSESSION, ZWAMEDIAITEM"
    status = "partial"

    def matches(self, f):
        return f.has("zwamessage", "zisfromme", "ztext", "zmessagedate") and "zwachatsession" in f.tables()

    def parse(self, f):
        con = f.connect()
        try:
            sessions = {}
            for r in con.execute("SELECT Z_PK, ZCONTACTJID, ZPARTNERNAME FROM ZWACHATSESSION"):
                sessions[r["Z_PK"]] = (r["ZCONTACTJID"], r["ZPARTNERNAME"])
            media = {}
            if f.has("zwamediaitem", "zmessage"):
                cols = ", ".join(safe_cols(f, "zwamediaitem", ["ZMESSAGE", "ZMEDIALOCALPATH", "ZLATITUDE", "ZLONGITUDE"]))
                for r in con.execute(f"SELECT {cols} FROM ZWAMEDIAITEM"):
                    media[r["ZMESSAGE"]] = r
            cols = ", ".join(safe_cols(f, "zwamessage", ["Z_PK", "ZISFROMME", "ZFROMJID", "ZTOJID", "ZTEXT",
                                                         "ZMESSAGEDATE", "ZCHATSESSION", "ZMESSAGETYPE", "ZPUSHNAME"]))
            for r in con.execute(f"SELECT {cols} FROM ZWAMESSAGE"):
                jid, partner = sessions.get(r["ZCHATSESSION"], (None, None))
                counterpart = r["ZTOJID"] if r["ZISFROMME"] else r["ZFROMJID"]
                ident = normalize_identifier(counterpart, f.default_cc) if counterpart else None
                ts, m = from_mac_absolute(r["ZMESSAGEDATE"]) if r["ZMESSAGEDATE"] else (None, None)
                mi = media.get(r["Z_PK"])
                lat = mi["ZLATITUDE"] if mi is not None else None
                lon = mi["ZLONGITUDE"] if mi is not None else None
                has_loc = lat not in (None, 0) and lon not in (None, 0)
                direction = "outgoing" if r["ZISFROMME"] else "incoming"
                yield ArtifactRecord(
                    category=Category.MESSAGE, subtype="whatsapp", timestamp=ts, timestamp_raw=str(r["ZMESSAGEDATE"]),
                    timestamp_method=m, identifiers=[ident] if ident and not str(ident).endswith("@g.us") else [],
                    names=[partner] if partner else [], direction=direction,
                    conversation_id=f"whatsapp:{jid}" if jid else None,
                    latitude=lat if has_loc else None, longitude=lon if has_loc else None,
                    location_kind="recorded" if has_loc else None,
                    summary=f"WhatsApp {direction} {partner or counterpart}: {(r['ZTEXT'] or '')[:120]}",
                    source_table="ZWAMESSAGE", source_rowid=str(r["Z_PK"]), raw=row_dict(r),
                    interpreted={"body": r["ZTEXT"] or "", "chat": jid, "partner_name": partner,
                                 "media_path": mi["ZMEDIALOCALPATH"] if mi is not None else None})
        finally:
            con.close()


class SmsBackupRestoreXmlAnalyzer(Analyzer):
    name = "export.sms_backup_restore_xml"
    version = "1.0"
    categories = (Category.MESSAGE, Category.CALL)
    description = "XML exports of the 'SMS Backup & Restore' Android app (<smses>, <calls>)."
    sources = "sms-*.xml (<smses><sms/><mms/>), calls-*.xml (<calls><call/>)"

    def matches(self, f):
        if f.detected_type != "xml":
            return False
        head = f.read_text(2048)
        return "<smses" in head or "<calls" in head

    def parse(self, f):
        idx = 0
        for _ev, el in iterparse(f.path):
            tag = el.tag
            if tag not in ("sms", "call", "mms"):
                continue
            idx += 1
            a = dict(el.attrib)
            if tag == "sms":
                t = int(a["type"]) if a.get("type", "").isdigit() else 0
                direction = {1: "incoming", 2: "outgoing"}.get(t, "unknown")
                ident = normalize_phone(a.get("address"), f.default_cc)
                ts = from_unix_millis(a["date"]) if a.get("date", "").isdigit() else None
                yield ArtifactRecord(category=Category.MESSAGE, subtype="sms", timestamp=ts, timestamp_raw=a.get("date"),
                                     timestamp_method="unix_ms", identifiers=[ident] if ident else [],
                                     names=[a["contact_name"]] if a.get("contact_name") not in (None, "", "(Unknown)") else [],
                                     direction=direction, conversation_id=f"sbr:{ident}" if ident else None,
                                     summary=f"SMS {direction} {a.get('address')}: {(a.get('body') or '')[:120]}",
                                     source_table="sms", source_rowid=str(idx), raw=a,
                                     interpreted={"body": a.get("body") or "", "counterpart": ident})
            elif tag == "call":
                t = int(a["type"]) if a.get("type", "").isdigit() else 0
                direction = {1: "incoming", 2: "outgoing", 3: "missed", 4: "voicemail", 5: "rejected", 6: "blocked"}.get(t, "unknown")
                ident = normalize_phone(a.get("number"), f.default_cc)
                ts = from_unix_millis(a["date"]) if a.get("date", "").isdigit() else None
                yield ArtifactRecord(category=Category.CALL, subtype="phone_call", timestamp=ts, timestamp_raw=a.get("date"),
                                     timestamp_method="unix_ms", identifiers=[ident] if ident else [],
                                     names=[a["contact_name"]] if a.get("contact_name") not in (None, "", "(Unknown)") else [],
                                     direction=direction, summary=f"Call {direction} {a.get('number')} ({a.get('duration')}s)",
                                     source_table="call", source_rowid=str(idx), raw=a,
                                     interpreted={"counterpart": ident, "duration_s": a.get("duration")})
            el.clear()


ANALYZERS = [WhatsAppAndroidAnalyzer(), WhatsAppIosAnalyzer(), SmsBackupRestoreXmlAnalyzer()]
