"""Pure correlation functions operating on lightweight event tuples.

Kept free of database code so they can be unit tested in isolation.
Every result lists the artefact ids that justify it and is classified as:

* ``observed_fact`` - mechanical equality observed in the data (same content
  hash, identical identifier)
* ``hypothesis``    - analytical association that requires examiner validation
* ``anomaly``       - temporal inconsistency to be investigated
"""
from __future__ import annotations

import math
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..core.timeutils import PLAUSIBLE_MIN, ensure_utc


@dataclass
class Ev:
    id: int
    category: str
    ts: datetime | None
    identifiers: list[str]
    names: list[str] = field(default_factory=list)
    content_hash: str = ""
    evidence_id: int = 0
    direction: str | None = None
    lat: float | None = None
    lon: float | None = None
    file_mtime: datetime | None = None
    summary: str = ""


@dataclass
class CorrelationResult:
    kind: str
    rule: str
    description: str
    artifact_ids: list[int]
    score: float = 1.0


def find_duplicates(events: list[Ev]) -> list[CorrelationResult]:
    groups = defaultdict(list)
    for e in events:
        if e.content_hash:
            groups[e.content_hash].append(e)
    out = []
    for h, items in groups.items():
        if len(items) < 2:
            continue
        sources = sorted({i.evidence_id for i in items})
        out.append(CorrelationResult(
            "observed_fact", "duplicate_content",
            f"{len(items)} {items[0].category} records share identical normalised content "
            f"(timestamp, identifiers, body) across {len(sources)} evidence source(s).",
            [i.id for i in items]))
    return out


def group_contacts(events: list[Ev]) -> list[CorrelationResult]:
    """Group contact records sharing at least one normalised identifier (union-find)."""
    contacts = [e for e in events if e.category == "contact" and e.identifiers]
    parent = {c.id: c.id for c in contacts}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    first_by_ident: dict[str, int] = {}
    for c in contacts:
        for ident in c.identifiers:
            if ident in first_by_ident:
                parent[find(c.id)] = find(first_by_ident[ident])
            else:
                first_by_ident[ident] = c.id
    groups = defaultdict(list)
    for c in contacts:
        groups[find(c.id)].append(c)
    out = []
    for members in groups.values():
        if len(members) < 2:
            continue
        shared = set.intersection(*(set(m.identifiers) for m in members)) or \
            {i for m in members for i in m.identifiers if sum(i in o.identifiers for o in members) > 1}
        names = sorted({n for m in members for n in m.names})
        out.append(CorrelationResult(
            "observed_fact", "contact_shared_identifier",
            f"{len(members)} contact records ({', '.join(names) or 'unnamed'}) share identifier(s) "
            f"{', '.join(sorted(shared))}: merge candidates (same person is an interpretation).",
            [m.id for m in members]))
    return out


def link_contacts(events: list[Ev]) -> list[CorrelationResult]:
    contacts = defaultdict(list)
    for e in events:
        if e.category == "contact":
            for ident in e.identifiers:
                contacts[ident].append(e)
    usage = defaultdict(list)
    for e in events:
        if e.category in ("message", "call"):
            for ident in e.identifiers:
                if ident in contacts:
                    usage[ident].append(e.id)
    out = []
    for ident, ids in usage.items():
        cs = contacts[ident]
        names = sorted({n for c in cs for n in c.names})
        out.append(CorrelationResult(
            "observed_fact", "identifier_matches_contact",
            f"Identifier {ident} used in {len(ids)} communication(s) equals the identifier stored in contact "
            f"record(s): {', '.join(names) or '(unnamed)'}.",
            [c.id for c in cs] + ids[:500]))
    return out


def call_message_proximity(events: list[Ev], window_minutes: int = 15) -> list[CorrelationResult]:
    win = timedelta(minutes=window_minutes)
    by_ident = defaultdict(lambda: {"call": [], "message": []})
    for e in events:
        if e.ts and e.category in ("call", "message"):
            for ident in e.identifiers:
                by_ident[ident][e.category].append(e)
    out = []
    for ident, d in by_ident.items():
        msgs = sorted(d["message"], key=lambda e: e.ts)
        times = [m.ts for m in msgs]
        for c in d["call"]:
            lo, hi = bisect_left(times, c.ts - win), bisect_right(times, c.ts + win)
            near = msgs[lo:hi]
            if near:
                out.append(CorrelationResult(
                    "hypothesis", "call_message_proximity",
                    f"Call with {ident} at {c.ts.isoformat()} and {len(near)} message(s) with the same counterpart "
                    f"within ±{window_minutes} min. Possible related exchange - to be validated by the examiner.",
                    [c.id] + [m.id for m in near], score=round(1 / (1 + len(near)), 2) if len(near) > 5 else 1.0))
    return out


def _haversine_m(lat1, lon1, lat2, lon2) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def colocated_events(events: list[Ev], minutes: int = 10, meters: float = 200) -> list[CorrelationResult]:
    geo = sorted([e for e in events if e.ts and e.lat is not None and e.lon is not None], key=lambda e: e.ts)
    out = []
    win = timedelta(minutes=minutes)
    for i, a in enumerate(geo):
        for b in geo[i + 1:]:
            if b.ts - a.ts > win:
                break
            if a.evidence_id == b.evidence_id and a.category == b.category:
                continue
            d = _haversine_m(a.lat, a.lon, b.lat, b.lon)
            if d <= meters:
                out.append(CorrelationResult(
                    "hypothesis", "spatio_temporal_proximity",
                    f"{a.category} and {b.category} records located {d:.0f} m apart within "
                    f"{(b.ts - a.ts).total_seconds() / 60:.1f} min. Co-location is an analytical inference.",
                    [a.id, b.id]))
                if len(out) > 2000:
                    return out
    return out


def temporal_anomalies(events: list[Ev], reference: datetime, exif_tolerance_hours: int = 24) -> list[CorrelationResult]:
    ref = ensure_utc(reference)
    out = []
    future = [e.id for e in events if e.ts and e.ts > ref + timedelta(days=1)]
    if future:
        out.append(CorrelationResult("anomaly", "future_timestamp",
                                     f"{len(future)} record(s) dated after the analysis date: possible clock change, "
                                     "wrong unit/epoch interpretation or scheduled items.", future[:1000]))
    old = [e.id for e in events if e.ts and e.ts < PLAUSIBLE_MIN and e.category not in ("contact",)]
    if old:
        out.append(CorrelationResult("anomaly", "implausible_old_timestamp",
                                     f"{len(old)} record(s) dated before 2000-01-01: likely default/zero values or "
                                     "wrong epoch.", old[:1000]))
    for e in events:
        if e.category == "media" and e.ts and e.file_mtime:
            delta = abs((ensure_utc(e.file_mtime) - e.ts).total_seconds()) / 3600
            if delta > exif_tolerance_hours:
                out.append(CorrelationResult(
                    "anomaly", "embedded_vs_filesystem_time",
                    f"Embedded capture time differs from file modification time by {delta:.0f} h "
                    "(may result from copy/transfer, editing or clock settings).", [e.id], score=0.5))
    return out


def activity_periods(timestamps: list[datetime], gap_minutes: int = 30) -> list[dict]:
    ts = sorted(ensure_utc(t) for t in timestamps if t)
    out = []
    if not ts:
        return out
    start = prev = ts[0]
    n = 1
    gap = timedelta(minutes=gap_minutes)
    for t in ts[1:]:
        if t - prev > gap:
            out.append({"start": start, "end": prev, "events": n})
            start, n = t, 0
        prev = t
        n += 1
    out.append({"start": start, "end": prev, "events": n})
    return out


def histogram(timestamps: list[datetime], bucket: str = "day", tz=None) -> list[tuple[str, int]]:
    c: Counter = Counter()
    for t in timestamps:
        if not t:
            continue
        t = ensure_utc(t).astimezone(tz) if tz else ensure_utc(t)
        key = {"hour": t.strftime("%Y-%m-%d %H:00"), "day": t.strftime("%Y-%m-%d"),
               "month": t.strftime("%Y-%m"), "hour_of_day": t.strftime("%H"),
               "weekday": t.strftime("%u %a")}[bucket]
        c[key] += 1
    return sorted(c.items())


def relationship_graph(events: list[Ev]) -> dict:
    """Bipartite graph: evidence sources (device owner side) <-> counterparts."""
    names = defaultdict(set)
    for e in events:
        if e.category == "contact":
            for i in e.identifiers:
                names[i].update(e.names)
    edges = Counter()
    kinds = defaultdict(Counter)
    for e in events:
        if e.category in ("message", "call"):
            for i in e.identifiers:
                edges[(e.evidence_id, i)] += 1
                kinds[(e.evidence_id, i)][e.category] += 1
                names[i].update(n for n in e.names if n)
    nodes = {}
    for (src, ident), w in edges.items():
        nodes.setdefault(f"ev:{src}", {"id": f"ev:{src}", "type": "source", "label": f"Evidence #{src}"})
        nodes.setdefault(ident, {"id": ident, "type": "counterpart",
                                 "label": (sorted(names[ident])[0] + f" ({ident})") if names.get(ident) else ident})
    return {"nodes": list(nodes.values()),
            "edges": [{"source": f"ev:{s}", "target": i, "weight": w, "kinds": dict(kinds[(s, i)])}
                      for (s, i), w in edges.most_common()]}
