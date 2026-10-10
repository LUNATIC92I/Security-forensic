"""Format-level analyzers for documented interchange formats."""
from __future__ import annotations

import csv
import io
import json
import quopri
import re
from datetime import datetime

from ..core.normalize import normalize_email, normalize_identifier, normalize_phone
from ..core.timeutils import auto_unix, parse_datetime
from .base import Analyzer, ArtifactRecord, Category
from .xmlsafe import iterparse, local


# ------------------------------------------------------------------ vCard
def _unfold(text: str) -> list[str]:
    lines = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if line[:1] in (" ", "\t") and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)
    return lines


def _prop(line: str):
    head, _, value = line.partition(":")
    parts = head.split(";")
    name = parts[0].split(".")[-1].upper()
    params = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        params[k.upper()] = v if v else k
    if params.get("ENCODING", "").upper() == "QUOTED-PRINTABLE":
        value = quopri.decodestring(value.encode()).decode(params.get("CHARSET", "utf-8"), errors="replace")
    return name, params, value


class VCardAnalyzer(Analyzer):
    name = "export.vcard"
    version = "1.0"
    categories = (Category.CONTACT,)
    description = "vCard 2.1/3.0/4.0 contact exports (RFC 6350)."
    sources = ".vcf"

    def matches(self, f):
        return f.detected_type == "vcard" or f.detected_type == "text" and f.read_text(64).lstrip().upper().startswith("BEGIN:VCARD")

    def parse(self, f):
        card, idx = None, 0
        for line in _unfold(f.read_text()):
            if not line.strip():
                continue
            name, params, value = _prop(line)
            if name == "BEGIN" and value.upper() == "VCARD":
                card = {"tel": [], "email": [], "fn": None, "n": None, "org": None, "props": []}
            elif name == "END" and value.upper() == "VCARD" and card is not None:
                idx += 1
                nm = card["fn"] or (" ".join(p for p in reversed((card["n"] or "").split(";")[:2]) if p)) or "(no name)"
                phones = [normalize_phone(t, f.default_cc) for t in card["tel"]]
                emails = [normalize_email(e) for e in card["email"]]
                yield ArtifactRecord(category=Category.CONTACT, subtype="vcard", summary=f"{nm} {' '.join(card['tel'])}".strip(),
                                     identifiers=[i for i in phones + emails if i], names=[nm], source_table="vcard",
                                     source_rowid=str(idx), raw={"properties": card["props"]},
                                     interpreted={"name": nm, "phones": phones, "phones_raw": card["tel"],
                                                  "emails": emails, "organization": card["org"]})
                card = None
            elif card is not None:
                card["props"].append([name, params, value])
                if name == "TEL":
                    card["tel"].append(value.replace("tel:", ""))
                elif name == "EMAIL":
                    card["email"].append(value)
                elif name == "FN":
                    card["fn"] = value
                elif name == "N":
                    card["n"] = value
                elif name == "ORG":
                    card["org"] = value.replace(";", " ").strip()


# -------------------------------------------------------------- iCalendar
def _ical_dt(value: str, params: dict, default_tz: str):
    tz = params.get("TZID", default_tz)
    v = value.strip()
    try:
        if params.get("VALUE") == "DATE" or re.fullmatch(r"\d{8}", v):
            return parse_datetime(datetime.strptime(v[:8], "%Y%m%d"), tz)[0], f"ical_date_{tz}"
        if v.endswith("Z"):
            return parse_datetime(datetime.strptime(v, "%Y%m%dT%H%M%SZ").isoformat() + "+00:00")[0], "ical_utc"
        return parse_datetime(datetime.strptime(v, "%Y%m%dT%H%M%S"), tz)[0], f"ical_local_{tz}"
    except (ValueError, KeyError):
        return None, None


class ICalendarAnalyzer(Analyzer):
    name = "export.icalendar"
    version = "1.0"
    categories = (Category.CALENDAR,)
    description = "iCalendar exports (RFC 5545): VEVENT and VTODO."
    sources = ".ics"

    def matches(self, f):
        return f.detected_type == "icalendar" or f.detected_type == "text" and f.read_text(64).lstrip().upper().startswith("BEGIN:VCALENDAR")

    def parse(self, f):
        comp, idx = None, 0
        for line in _unfold(f.read_text()):
            if not line.strip():
                continue
            name, params, value = _prop(line)
            if name == "BEGIN" and value.upper() in ("VEVENT", "VTODO"):
                comp = {"type": value.upper(), "props": {}, "params": {}}
            elif name == "END" and comp is not None and value.upper() == comp["type"]:
                idx += 1
                p = comp["props"]
                key = "DTSTART" if "DTSTART" in p else "DUE"
                ts, method = _ical_dt(p.get(key, ""), comp["params"].get(key, {}), f.default_tz) if p.get(key) else (None, None)
                text = p.get("DESCRIPTION", "").replace("\\n", "\n").replace("\\,", ",")
                yield ArtifactRecord(category=Category.CALENDAR, subtype=comp["type"].lower(), timestamp=ts,
                                     timestamp_raw=p.get(key), timestamp_method=method,
                                     summary=f"{'Event' if comp['type'] == 'VEVENT' else 'Task'}: {p.get('SUMMARY', '')} @ {p.get('LOCATION', '')}",
                                     source_table=comp["type"], source_rowid=p.get("UID", str(idx)), raw=p,
                                     interpreted={"title": p.get("SUMMARY"), "location": p.get("LOCATION"), "text": text})
                comp = None
            elif comp is not None:
                comp["props"][name] = value
                comp["params"][name] = params


# ------------------------------------------------- LUNATIC exchange format
EXCHANGE_CATS = {"contact": Category.CONTACT, "message": Category.MESSAGE, "call": Category.CALL,
                 "location": Category.LOCATION, "calendar": Category.CALENDAR, "note": Category.NOTE,
                 "browser": Category.BROWSER}


def exchange_record(rec: dict, idx: int, f) -> ArtifactRecord | None:
    cat = EXCHANGE_CATS.get(str(rec.get("category", "")).lower())
    if cat is None:
        return None
    ts, method = parse_datetime(rec.get("timestamp"), f.default_tz) if rec.get("timestamp") not in (None, "") else (None, None)
    cps = rec.get("counterparts") or ([rec["counterpart"]] if rec.get("counterpart") else [])
    if isinstance(cps, str):
        cps = [c for c in re.split(r"[;|]", cps) if c]
    ids = [normalize_identifier(c, f.default_cc) for c in cps]
    lat, lon = rec.get("latitude"), rec.get("longitude")
    try:
        lat = float(lat) if lat not in (None, "") else None
        lon = float(lon) if lon not in (None, "") else None
    except ValueError:
        lat = lon = None
    body = rec.get("body") or rec.get("text") or ""
    name = rec.get("name")
    return ArtifactRecord(
        category=cat, subtype=str(rec.get("subtype") or "exchange"), timestamp=ts, timestamp_raw=str(rec.get("timestamp") or ""),
        timestamp_method=method, identifiers=[i for i in ids if i], names=[name] if name else [],
        direction=rec.get("direction"), conversation_id=rec.get("conversation_id") or None,
        latitude=lat, longitude=lon, location_kind=(rec.get("location_kind") or "recorded") if lat is not None else None,
        summary=f"{cat.value} {rec.get('direction') or ''} {' '.join(cps)} {name or ''}: {body[:120]}".replace("  ", " "),
        source_table="records", source_rowid=str(rec.get("id") or idx), raw=rec,
        interpreted={"body": body, "duration_s": rec.get("duration"), "url": rec.get("url"), "title": rec.get("title")})


class ExchangeFormatAnalyzer(Analyzer):
    name = "export.lunatic_exchange"
    version = "1.0"
    categories = tuple(EXCHANGE_CATS.values())
    description = "LUNATIC exchange format (JSON or CSV) documented in docs/exchange_format.md."
    sources = "*.json {'format': 'lunatic-exchange'} | *.csv with header category,timestamp,..."

    def matches(self, f):
        if f.detected_type == "json":
            return '"lunatic-exchange"' in f.read_text(1024)
        if f.detected_type in ("csv", "text"):
            first = f.read_text(1024).splitlines()[:1]
            return bool(first) and first[0].lower().startswith("category,timestamp")
        return False

    def parse(self, f):
        if f.detected_type == "json":
            doc = json.loads(f.read_text())
            if doc.get("format") != "lunatic-exchange" or int(doc.get("version", 0)) != 1:
                return
            records = doc.get("records") or []
        else:
            records = list(csv.DictReader(io.StringIO(f.read_text())))
        for i, rec in enumerate(records, 1):
            if isinstance(rec, dict):
                r = exchange_record(rec, i, f)
                if r:
                    yield r


# ------------------------------------------------------- location history
def _latlng_str(s: str):
    m = re.match(r"\s*(-?\d+(?:\.\d+)?)°?,\s*(-?\d+(?:\.\d+)?)°?", s or "")
    return (float(m.group(1)), float(m.group(2))) if m else (None, None)


class GoogleLocationHistoryAnalyzer(Analyzer):
    name = "export.google_location_history"
    version = "1.0"
    categories = (Category.LOCATION,)
    description = ("Google location history exports: Takeout Records.json and on-device Timeline export "
                   "(rawSignals / timelinePath).")
    sources = "Records.json {'locations': [...]}, Timeline.json {'semanticSegments', 'rawSignals'}"
    status = "partial"

    def matches(self, f):
        if f.detected_type != "json":
            return False
        head = f.read_text(4096)
        return '"latitudeE7"' in head or '"semanticSegments"' in head or '"rawSignals"' in head

    def parse(self, f):
        doc = json.loads(f.read_text(512 * 1024 * 1024))
        for i, loc in enumerate(doc.get("locations", []) or [], 1):
            if "latitudeE7" not in loc:
                continue
            lat, lon = loc["latitudeE7"] / 1e7, loc["longitudeE7"] / 1e7
            if "timestamp" in loc:
                ts, m = parse_datetime(loc["timestamp"])
            else:
                ts, m = auto_unix(loc.get("timestampMs"))
            src = (loc.get("source") or "").upper()
            acc = loc.get("accuracy")
            estimated = src in ("WIFI", "CELL") or (acc is not None and acc > 100)
            yield ArtifactRecord(category=Category.LOCATION, subtype="google_records", timestamp=ts,
                                 timestamp_raw=str(loc.get("timestamp") or loc.get("timestampMs")), timestamp_method=m,
                                 latitude=lat, longitude=lon, location_kind="estimated" if estimated else "recorded",
                                 summary=f"Location {lat:.5f},{lon:.5f} (source {src or '?'}, ±{acc or '?'} m)",
                                 source_table="locations", source_rowid=str(i), raw=loc,
                                 interpreted={"accuracy_m": acc, "source": src,
                                              "classification_rule": "estimated if source WIFI/CELL or accuracy > 100 m"})
        idx = 0
        for sig in doc.get("rawSignals", []) or []:
            pos = sig.get("position")
            if not pos:
                continue
            idx += 1
            lat, lon = _latlng_str(pos.get("LatLng") or pos.get("latLng"))
            if lat is None:
                continue
            ts, m = parse_datetime(pos.get("timestamp"))
            acc = pos.get("accuracyMeters")
            src = (pos.get("source") or "").upper()
            estimated = src in ("WIFI", "CELL") or (acc is not None and acc > 100)
            yield ArtifactRecord(category=Category.LOCATION, subtype="google_timeline_signal", timestamp=ts,
                                 timestamp_raw=pos.get("timestamp"), timestamp_method=m, latitude=lat, longitude=lon,
                                 location_kind="estimated" if estimated else "recorded",
                                 summary=f"Location {lat:.5f},{lon:.5f} (source {src or '?'}, ±{acc or '?'} m)",
                                 source_table="rawSignals", source_rowid=str(idx), raw=pos,
                                 interpreted={"accuracy_m": acc, "source": src})
        for seg in doc.get("semanticSegments", []) or []:
            for pt in seg.get("timelinePath", []) or []:
                idx += 1
                lat, lon = _latlng_str(pt.get("point"))
                if lat is None:
                    continue
                ts, m = parse_datetime(pt.get("time"))
                yield ArtifactRecord(category=Category.LOCATION, subtype="google_timeline_path", timestamp=ts,
                                     timestamp_raw=pt.get("time"), timestamp_method=m, latitude=lat, longitude=lon,
                                     location_kind="estimated", summary=f"Timeline path point {lat:.5f},{lon:.5f}",
                                     source_table="semanticSegments.timelinePath", source_rowid=str(idx), raw=pt,
                                     interpreted={"note": "path points are inferred by the provider (estimated)"})


class GpxAnalyzer(Analyzer):
    name = "export.gpx"
    version = "1.0"
    categories = (Category.LOCATION,)
    description = "GPS Exchange Format tracks and waypoints."
    sources = ".gpx (trkpt, rtept, wpt)"

    def matches(self, f):
        return f.detected_type == "xml" and "<gpx" in f.read_text(2048)

    def parse(self, f):
        idx = 0
        for _ev, el in iterparse(f.path):
            tag = local(el.tag)
            if tag in ("trkpt", "wpt", "rtept"):
                idx += 1
                try:
                    lat, lon = float(el.get("lat")), float(el.get("lon"))
                except (TypeError, ValueError):
                    continue
                t = next((c.text for c in el if local(c.tag) == "time"), None)
                name = next((c.text for c in el if local(c.tag) == "name"), None)
                ts, m = parse_datetime(t) if t else (None, None)
                yield ArtifactRecord(category=Category.LOCATION, subtype=f"gpx_{tag}", timestamp=ts, timestamp_raw=t,
                                     timestamp_method=m, latitude=lat, longitude=lon, location_kind="recorded",
                                     summary=f"GPX {tag} {lat:.5f},{lon:.5f} {name or ''}", source_table=tag,
                                     source_rowid=str(idx), raw=dict(el.attrib), interpreted={"name": name})
                el.clear()


# ---------------------------------------------------------------- logs
LOGCAT = re.compile(r"^(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEFS])\s+([^:]*?)\s*: (.*)$")
SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^\[:]+)(?:\[(\d+)\])?: (.*)$")
ISO_LOG = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)$")
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


class LogAnalyzer(Analyzer):
    name = "logs.system"
    version = "1.0"
    categories = (Category.LOG,)
    description = "Exported system logs: Android logcat (threadtime), BSD syslog, ISO-8601 timestamped lines."
    sources = "logcat.txt, syslog, *.log"
    MAX_LINES = 100_000

    def _kind(self, f):
        if f.detected_type not in ("text", "csv"):
            return None
        lines = [l for l in f.read_text(8192).splitlines() if l.strip()][:20]
        if not lines:
            return None
        for kind, rx in (("logcat", LOGCAT), ("syslog", SYSLOG), ("iso", ISO_LOG)):
            if sum(1 for l in lines if rx.match(l)) >= max(1, -(-len(lines) // 2)):
                return kind
        return None

    def matches(self, f):
        return self._kind(f) is not None

    def parse(self, f):
        kind = self._kind(f)
        year = (f.mtime or datetime.now()).year
        n = 0
        for i, line in enumerate(f.read_text().splitlines(), 1):
            if n >= self.MAX_LINES:
                break
            ts = method = None
            interp = {}
            if kind == "logcat" and (m := LOGCAT.match(line)):
                mo, d, h, mi, s, ms, pid, tid, lvl, tag, msg = m.groups()
                try:
                    ts, _ = parse_datetime(datetime(year, int(mo), int(d), int(h), int(mi), int(s), int(ms) * 1000), f.default_tz)
                except ValueError:
                    ts = None
                method = f"logcat_year_assumed_{year}_tz_{f.default_tz}"
                interp = {"level": lvl, "tag": tag, "pid": pid, "tid": tid, "text": msg, "estimated_year": True}
            elif kind == "syslog" and (m := SYSLOG.match(line)):
                mon, d, h, mi, s, host, proc, pid, msg = m.groups()
                try:
                    ts, _ = parse_datetime(datetime(year, MONTHS.get(mon, 1), int(d), int(h), int(mi), int(s)), f.default_tz)
                except ValueError:
                    ts = None
                method = f"syslog_year_assumed_{year}_tz_{f.default_tz}"
                interp = {"host": host, "process": proc, "pid": pid, "text": msg, "estimated_year": True}
            elif kind == "iso" and (m := ISO_LOG.match(line)):
                ts, method = parse_datetime(m.group(1), f.default_tz)
                interp = {"text": m.group(2)}
            else:
                continue
            n += 1
            yield ArtifactRecord(category=Category.LOG, subtype=kind, timestamp=ts, timestamp_raw=line[:40],
                                 timestamp_method=method, summary=line[:300], source_table="line", source_rowid=str(i),
                                 raw={"line": line[:4000]}, interpreted=interp)


ANALYZERS = [VCardAnalyzer(), ICalendarAnalyzer(), ExchangeFormatAnalyzer(), GoogleLocationHistoryAnalyzer(),
             GpxAnalyzer(), LogAnalyzer()]
