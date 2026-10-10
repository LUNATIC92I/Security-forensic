from datetime import datetime, timedelta, timezone

from lunatic_forensics.correlation import engine as E

UTC = timezone.utc
T0 = datetime(2026, 3, 14, 8, 0, tzinfo=UTC)


def ev(i, cat, minutes=None, ids=(), names=(), h="", src=1, lat=None, lon=None):
    return E.Ev(i, cat, T0 + timedelta(minutes=minutes) if minutes is not None else None, list(ids), list(names), h, src,
                lat=lat, lon=lon)


def test_duplicates_across_sources():
    r = E.find_duplicates([ev(1, "message", 0, h="a", src=1), ev(2, "message", 0, h="a", src=2), ev(3, "message", 0, h="b")])
    assert len(r) == 1 and r[0].artifact_ids == [1, 2] and r[0].kind == "observed_fact"
    assert "2 evidence source" in r[0].description


def test_group_and_link_contacts():
    evs = [ev(1, "contact", ids=["+331"], names=["Bob"]), ev(2, "contact", ids=["+331", "b@x.org"], names=["Bobby"]),
           ev(3, "contact", ids=["+332"], names=["Claire"]), ev(4, "message", 0, ids=["+331"]), ev(5, "call", 1, ids=["+331"])]
    g = E.group_contacts(evs)
    assert len(g) == 1 and sorted(g[0].artifact_ids) == [1, 2] and "+331" in g[0].description
    links = E.link_contacts(evs)
    assert len(links) == 1 and set(links[0].artifact_ids) == {1, 2, 4, 5}


def test_call_message_proximity_is_hypothesis():
    evs = [ev(1, "call", 10, ids=["+331"]), ev(2, "message", 0, ids=["+331"]), ev(3, "message", 40, ids=["+331"]),
           ev(4, "message", 12, ids=["+332"])]
    r = E.call_message_proximity(evs, 15)
    assert len(r) == 1 and r[0].kind == "hypothesis" and r[0].artifact_ids == [1, 2]


def test_colocation():
    evs = [ev(1, "media", 0, lat=48.8443, lon=2.3738), ev(2, "location", 5, lat=48.8444, lon=2.3739, src=2),
           ev(3, "location", 5, lat=45.0, lon=5.0, src=2)]
    r = E.colocated_events(evs)
    assert len(r) == 1 and r[0].artifact_ids == [1, 2] and r[0].kind == "hypothesis"


def test_temporal_anomalies():
    future = ev(1, "message", 60 * 24 * 365)
    old = E.Ev(2, "call", datetime(1980, 1, 1, tzinfo=UTC), [])
    media = ev(3, "media", 0)
    media.file_mtime = T0 + timedelta(days=10)
    r = {x.rule: x for x in E.temporal_anomalies([future, old, media], T0)}
    assert r["future_timestamp"].artifact_ids == [1]
    assert r["implausible_old_timestamp"].artifact_ids == [2]
    assert r["embedded_vs_filesystem_time"].artifact_ids == [3]


def test_activity_and_histogram():
    ts = [T0, T0 + timedelta(minutes=10), T0 + timedelta(hours=5), T0 + timedelta(days=1)]
    p = E.activity_periods(ts, 30)
    assert [x["events"] for x in p] == [2, 1, 1]
    assert E.histogram(ts, "day") == [("2026-03-14", 3), ("2026-03-15", 1)]
    assert dict(E.histogram(ts, "hour_of_day"))["08"] == 3


def test_graph():
    g = E.relationship_graph([ev(1, "contact", ids=["+331"], names=["Bob"]), ev(2, "message", 0, ids=["+331"]),
                              ev(3, "call", 0, ids=["+331"]), ev(4, "message", 0, ids=["+332"])])
    assert {n["id"] for n in g["nodes"]} == {"ev:1", "+331", "+332"}
    e = next(e for e in g["edges"] if e["target"] == "+331")
    assert e["weight"] == 2 and e["kinds"] == {"message": 1, "call": 1}
    assert next(n for n in g["nodes"] if n["id"] == "+331")["label"].startswith("Bob")
