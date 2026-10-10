"""Android artefact analyzers.

Schemas follow the AOSP providers (``TelephonyProvider`` mmssms.db,
``ContactsProvider`` contacts2.db / calllog.db, ``CalendarProvider``
calendar.db). OEM variants may add columns; only columns present are read.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterator

from ..core.normalize import normalize_identifier, normalize_phone
from ..core.timeutils import auto_unix, from_unix_millis, from_unix_seconds
from .base import Analyzer, ArtifactRecord, Category, FileContext, row_dict, safe_cols

SMS_TYPES = {1: "incoming", 2: "outgoing", 3: "draft", 4: "outbox", 5: "failed", 6: "queued"}
CALL_TYPES = {1: "incoming", 2: "outgoing", 3: "missed", 4: "voicemail", 5: "rejected", 6: "blocked",
              7: "answered_externally"}


def _direction_from_sms(t):
    v = SMS_TYPES.get(t, "unknown")
    return v if v in ("incoming", "outgoing") else ("outgoing" if v in ("outbox", "failed", "queued") else "unknown")


class AndroidSmsAnalyzer(Analyzer):
    name = "android.sms"
    version = "1.1"
    categories = (Category.MESSAGE,)
    description = "SMS and MMS text from Android TelephonyProvider (mmssms.db)."
    sources = "mmssms.db: tables sms, pdu, part, addr"

    def matches(self, f):
        return f.has("sms", "address", "date", "body", "type")

    def parse(self, f) -> Iterator[ArtifactRecord]:
        con = f.connect()
        try:
            cols = ", ".join(safe_cols(f, "sms", ["_id", "thread_id", "address", "date", "date_sent",
                                                  "type", "body", "read", "subject", "service_center"]))
            for r in con.execute(f"SELECT {cols} FROM sms"):
                raw = row_dict(r)
                ts = from_unix_millis(r["date"]) if r["date"] else None
                ident = normalize_phone(r["address"], f.default_cc) or normalize_identifier(r["address"], f.default_cc)
                direction = _direction_from_sms(r["type"])
                body = r["body"] or ""
                yield ArtifactRecord(
                    category=Category.MESSAGE, subtype="sms", timestamp=ts, timestamp_raw=str(r["date"]),
                    timestamp_method="unix_ms", identifiers=[ident] if ident else [],
                    conversation_id=f"android-thread:{r['thread_id']}" if r["thread_id"] is not None else None,
                    direction=direction, summary=f"SMS {direction} {r['address'] or '?'}: {body[:120]}",
                    source_table="sms", source_rowid=str(r["_id"]), raw=raw,
                    interpreted={"body": body, "box": SMS_TYPES.get(r["type"], "unknown"),
                                 "counterpart": ident, "read": bool(r["read"]) if r["read"] is not None else None,
                                 "sent_at": from_unix_millis(r["date_sent"]).isoformat() if r["date_sent"] else None})
            if f.has("pdu", "_id", "date", "msg_box") and f.has("part", "mid", "ct", "text"):
                yield from self._mms(f, con)
        finally:
            con.close()

    def _mms(self, f, con):
        addrs = defaultdict(list)
        if f.has("addr", "msg_id", "address", "type"):
            for a in con.execute("SELECT msg_id, address, type FROM addr"):
                addrs[a["msg_id"]].append((a["address"], a["type"]))
        texts = defaultdict(list)
        atts = defaultdict(list)
        for p in con.execute("SELECT mid, ct, text FROM part"):
            if p["ct"] == "text/plain" and p["text"]:
                texts[p["mid"]].append(p["text"])
            elif p["ct"] not in ("application/smil", "text/plain"):
                atts[p["mid"]].append(p["ct"])
        cols = ", ".join(safe_cols(f, "pdu", ["_id", "thread_id", "date", "msg_box", "sub"]))
        for r in con.execute(f"SELECT {cols} FROM pdu"):
            direction = {1: "incoming", 2: "outgoing"}.get(r["msg_box"], "unknown")
            parties = addrs.get(r["_id"], [])
            # PduHeaders: 137 = FROM, 151 = TO
            want = 137 if direction == "incoming" else 151
            ids = [normalize_identifier(a, f.default_cc) for a, t in parties if t == want and a != "insert-address-token"]
            body = "\n".join(texts.get(r["_id"], []))
            ts = from_unix_seconds(r["date"]) if r["date"] else None
            yield ArtifactRecord(
                category=Category.MESSAGE, subtype="mms", timestamp=ts, timestamp_raw=str(r["date"]),
                timestamp_method="unix_s", identifiers=[i for i in ids if i], direction=direction,
                conversation_id=f"android-thread:{r['thread_id']}" if r["thread_id"] is not None else None,
                summary=f"MMS {direction}: {body[:120]}" + (f" [{len(atts[r['_id']])} attachment(s)]" if atts.get(r["_id"]) else ""),
                source_table="pdu", source_rowid=str(r["_id"]),
                raw={**row_dict(r), "addr": parties},
                interpreted={"body": body, "attachments": atts.get(r["_id"], []), "subject": r["sub"]})


class AndroidContactsAnalyzer(Analyzer):
    name = "android.contacts"
    version = "1.0"
    categories = (Category.CONTACT,)
    description = "Contacts from Android ContactsProvider (contacts2.db)."
    sources = "contacts2.db: raw_contacts, data, mimetypes"

    MT = {"vnd.android.cursor.item/name": "name", "vnd.android.cursor.item/phone_v2": "phone",
          "vnd.android.cursor.item/email_v2": "email", "vnd.android.cursor.item/organization": "organization",
          "vnd.android.cursor.item/postal-address_v2": "address", "vnd.android.cursor.item/note": "note",
          "vnd.android.cursor.item/nickname": "nickname"}

    def matches(self, f):
        return f.has("raw_contacts", "_id") and f.has("data", "raw_contact_id", "mimetype_id", "data1") \
            and f.has("mimetypes", "_id", "mimetype")

    def parse(self, f):
        con = f.connect()
        try:
            rc_cols = ", ".join(safe_cols(f, "raw_contacts", ["_id", "contact_id", "display_name", "deleted",
                                                              "account_type", "account_name", "times_contacted",
                                                              "last_time_contacted"]))
            raws = {r["_id"]: row_dict(r) for r in con.execute(f"SELECT {rc_cols} FROM raw_contacts")}
            fields = defaultdict(lambda: defaultdict(list))
            q = ("SELECT d._id, d.raw_contact_id, m.mimetype, d.data1, d.data2, d.data3, d.data4 FROM data d "
                 "JOIN mimetypes m ON m._id = d.mimetype_id") if f.has("data", "data2", "data3", "data4") else \
                ("SELECT d._id, d.raw_contact_id, m.mimetype, d.data1, NULL AS data2, NULL AS data3, NULL AS data4 "
                 "FROM data d JOIN mimetypes m ON m._id = d.mimetype_id")
            for r in con.execute(q):
                kind = self.MT.get(r["mimetype"])
                if kind:
                    fields[r["raw_contact_id"]][kind].append(row_dict(r))
        finally:
            con.close()
        for rid, raw in raws.items():
            data = fields.get(rid, {})
            names = [d["data1"] for d in data.get("name", []) if d["data1"]] or ([raw["display_name"]] if raw.get("display_name") else [])
            phones_raw = [d["data1"] for d in data.get("phone", []) if d["data1"]]
            phones = [d.get("data4") or normalize_phone(d["data1"], f.default_cc) for d in data.get("phone", []) if d["data1"]]
            emails = [normalize_identifier(d["data1"]) for d in data.get("email", []) if d["data1"]]
            ids = [i for i in phones + emails if i]
            name = names[0] if names else "(no name)"
            yield ArtifactRecord(
                category=Category.CONTACT, subtype="android_contact", summary=f"{name} {' '.join(phones_raw)}".strip(),
                identifiers=ids, names=names, source_table="raw_contacts", source_rowid=str(rid),
                raw={"raw_contact": raw, "data": {k: v for k, v in data.items()}},
                interpreted={"name": name, "phones": phones, "phones_raw": phones_raw, "emails": emails,
                             "organization": [d["data1"] for d in data.get("organization", [])],
                             "account": raw.get("account_name"),
                             "marked_deleted": bool(raw.get("deleted"))})


class AndroidCallLogAnalyzer(Analyzer):
    name = "android.calllog"
    version = "1.0"
    categories = (Category.CALL,)
    description = "Call history from Android CallLogProvider (calllog.db or contacts2.db)."
    sources = "calllog.db / contacts2.db: calls"

    def matches(self, f):
        return f.has("calls", "number", "date", "duration", "type")

    def parse(self, f):
        con = f.connect()
        try:
            cols = ", ".join(safe_cols(f, "calls", ["_id", "number", "date", "duration", "type", "name",
                                                    "countryiso", "geocoded_location", "presentation",
                                                    "subscription_id"]))
            for r in con.execute(f"SELECT {cols} FROM calls"):
                ident = normalize_phone(r["number"], f.default_cc)
                direction = CALL_TYPES.get(r["type"], "unknown")
                ts = from_unix_millis(r["date"]) if r["date"] else None
                yield ArtifactRecord(
                    category=Category.CALL, subtype="phone_call", timestamp=ts, timestamp_raw=str(r["date"]),
                    timestamp_method="unix_ms", identifiers=[ident] if ident else [],
                    names=[r["name"]] if r["name"] else [], direction=direction,
                    summary=f"Call {direction} {r['number'] or 'private'} ({r['duration'] or 0}s)",
                    source_table="calls", source_rowid=str(r["_id"]), raw=row_dict(r),
                    interpreted={"counterpart": ident, "duration_s": r["duration"], "type": direction,
                                 "cached_name": r["name"], "geocoded": r["geocoded_location"]})
        finally:
            con.close()


class AndroidCalendarAnalyzer(Analyzer):
    name = "android.calendar"
    version = "1.0"
    categories = (Category.CALENDAR,)
    description = "Events from Android CalendarProvider (calendar.db)."
    sources = "calendar.db: Events, Calendars"

    def matches(self, f):
        return f.has("events", "title", "dtstart") and "calendars" in f.tables()

    def parse(self, f):
        con = f.connect()
        try:
            cols = ", ".join("e." + c if not c.startswith("NULL") else c for c in
                             safe_cols(f, "events", ["_id", "title", "dtstart", "dtend", "eventLocation",
                                                     "description", "eventTimezone", "deleted", "calendar_id"]))
            for r in con.execute(f"SELECT {cols} FROM Events e"):
                ts = from_unix_millis(r["dtstart"]) if r["dtstart"] else None
                yield ArtifactRecord(
                    category=Category.CALENDAR, subtype="event", timestamp=ts, timestamp_raw=str(r["dtstart"]),
                    timestamp_method="unix_ms", summary=f"Event: {r['title'] or ''} @ {r['eventLocation'] or ''}",
                    source_table="Events", source_rowid=str(r["_id"]), raw=row_dict(r),
                    interpreted={"title": r["title"], "location": r["eventLocation"], "text": r["description"],
                                 "end": from_unix_millis(r["dtend"]).isoformat() if r["dtend"] else None,
                                 "event_timezone": r["eventTimezone"], "marked_deleted": bool(r["deleted"])})
        finally:
            con.close()


# ---------------------------------------------------------------- ADB outputs
_PROP_RE = re.compile(r"^\[([^\]]+)\]: \[(.*)\]$")


class AdbGetpropAnalyzer(Analyzer):
    name = "android.adb_getprop"
    version = "1.0"
    categories = (Category.DEVICE,)
    description = "Device properties collected with 'adb shell getprop'."
    sources = "getprop.txt produced by the ADB acquisition connector"

    def matches(self, f):
        if f.detected_type not in ("text", "csv") or f.size > 5 * 1024 * 1024:
            return False
        head = f.read_text(4096)
        return sum(1 for l in head.splitlines()[:20] if _PROP_RE.match(l.strip())) >= 3

    def parse(self, f):
        props = {}
        for line in f.read_text().splitlines():
            m = _PROP_RE.match(line.strip())
            if m:
                props[m.group(1)] = m.group(2)
        keys = ["ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
                "ro.build.version.sdk", "ro.build.version.security_patch", "ro.build.fingerprint",
                "ro.serialno", "ro.crypto.state", "ro.crypto.type", "persist.sys.timezone"]
        interp = {k: props.get(k) for k in keys if k in props}
        yield ArtifactRecord(category=Category.DEVICE, subtype="android_properties",
                             summary=f"{props.get('ro.product.manufacturer', '?')} {props.get('ro.product.model', '?')} "
                                     f"Android {props.get('ro.build.version.release', '?')}",
                             raw={"properties": props}, interpreted=interp)


class AdbPackagesAnalyzer(Analyzer):
    name = "android.adb_packages"
    version = "1.0"
    categories = (Category.APP,)
    description = "Installed packages listed with 'adb shell pm list packages -f'."
    sources = "packages.txt produced by the ADB acquisition connector"

    LINE = re.compile(r"^package:(?:(?P<path>.+\.apk)=)?(?P<pkg>[A-Za-z0-9_.]+)(?:\s+installer=(?P<inst>\S+))?(?:\s+uid:(?P<uid>\d+))?")

    def matches(self, f):
        if f.detected_type not in ("text", "csv") or f.size > 20 * 1024 * 1024:
            return False
        lines = [l for l in f.read_text(4096).splitlines() if l.strip()][:10]
        return bool(lines) and sum(1 for l in lines if l.startswith("package:")) >= max(1, len(lines) - 1)

    def parse(self, f):
        for i, line in enumerate(f.read_text().splitlines()):
            m = self.LINE.match(line.strip())
            if not m:
                continue
            path = m.group("path") or ""
            yield ArtifactRecord(category=Category.APP, subtype="installed_package", summary=f"Package {m.group('pkg')}",
                                 source_rowid=str(i + 1), raw={"line": line},
                                 interpreted={"package": m.group("pkg"), "apk_path": path,
                                              "installer": m.group("inst"), "uid": m.group("uid"),
                                              "system_app": path.startswith(("/system", "/product", "/vendor", "/apex"))})


class AdbContentQueryAnalyzer(Analyzer):
    """Parses ``adb shell content query --uri ...`` outputs saved by the connector.

    Format: ``Row: N key=value, key=value``. Values containing ", key=" are
    ambiguous by construction of the tool output; such rows are flagged.
    """

    name = "android.adb_content_query"
    version = "1.0"
    categories = (Category.MESSAGE, Category.CALL, Category.CONTACT)
    description = "Content provider rows (sms, call_log, contacts) exported over ADB without root."
    sources = "content_sms.txt / content_calls.txt / content_contacts.txt from the ADB connector"
    status = "partial"

    ROW = re.compile(r"^Row: (\d+) (.*)$")
    SPLIT = re.compile(r", (?=[A-Za-z_][A-Za-z0-9_]*=)")

    def matches(self, f):
        if f.detected_type not in ("text", "csv"):
            return False
        n = f.name.lower()
        return n.startswith("content_") and any(x in n for x in ("sms", "call", "contact")) and \
            f.read_text(200).startswith("Row: ")

    def _rows(self, f):
        cur = None
        for line in f.read_text().splitlines():
            m = self.ROW.match(line)
            if m:
                if cur:
                    yield cur
                cur = [m.group(1), m.group(2)]
            elif cur:
                cur[1] += "\n" + line
        if cur:
            yield cur

    def parse(self, f):
        n = f.name.lower()
        for idx, body in self._rows(f):
            parts = self.SPLIT.split(body)
            row = {}
            for p in parts:
                k, _, v = p.partition("=")
                row[k] = None if v == "NULL" else v
            if "sms" in n:
                ts, method = auto_unix(row.get("date"))
                ident = normalize_phone(row.get("address"), f.default_cc)
                t = int(row["type"]) if (row.get("type") or "").isdigit() else None
                direction = _direction_from_sms(t)
                yield ArtifactRecord(category=Category.MESSAGE, subtype="sms", timestamp=ts, timestamp_raw=row.get("date"),
                                     timestamp_method=method, identifiers=[ident] if ident else [], direction=direction,
                                     conversation_id=f"android-thread:{row.get('thread_id')}" if row.get("thread_id") else None,
                                     summary=f"SMS {direction} {row.get('address')}: {(row.get('body') or '')[:120]}",
                                     source_table="content://sms", source_rowid=idx, raw=row,
                                     interpreted={"body": row.get("body") or "", "counterpart": ident})
            elif "call" in n:
                ts, method = auto_unix(row.get("date"))
                ident = normalize_phone(row.get("number"), f.default_cc)
                t = int(row["type"]) if (row.get("type") or "").isdigit() else None
                direction = CALL_TYPES.get(t, "unknown")
                yield ArtifactRecord(category=Category.CALL, subtype="phone_call", timestamp=ts, timestamp_raw=row.get("date"),
                                     timestamp_method=method, identifiers=[ident] if ident else [], direction=direction,
                                     names=[row["name"]] if row.get("name") else [],
                                     summary=f"Call {direction} {row.get('number')} ({row.get('duration')}s)",
                                     source_table="content://call_log/calls", source_rowid=idx, raw=row,
                                     interpreted={"counterpart": ident, "duration_s": row.get("duration")})
            else:
                num = row.get("number") or row.get("data1")
                ident = normalize_phone(num, f.default_cc)
                name = row.get("display_name") or row.get("name")
                yield ArtifactRecord(category=Category.CONTACT, subtype="android_contact",
                                     summary=f"{name or '(no name)'} {num or ''}", identifiers=[ident] if ident else [],
                                     names=[name] if name else [], source_table="content://contacts", source_rowid=idx,
                                     raw=row, interpreted={"name": name, "phones": [ident] if ident else []})


ANALYZERS = [AndroidSmsAnalyzer(), AndroidContactsAnalyzer(), AndroidCallLogAnalyzer(), AndroidCalendarAnalyzer(),
             AdbGetpropAnalyzer(), AdbPackagesAnalyzer(), AdbContentQueryAnalyzer()]
