# LUNATIC exchange format v1

A simple, documented format to import records produced by other tools or manual transcriptions.

## JSON

```json
{"format": "lunatic-exchange", "version": 1,
 "source": {"tool": "name", "version": "x.y", "note": "free text"},
 "records": [
   {"id": "r1", "category": "message", "timestamp": "2026-03-16T10:00:00Z", "direction": "incoming",
    "counterpart": "+33639980003", "body": "text", "conversation_id": "conv-1"},
   {"id": "r2", "category": "call", "timestamp": "2026-03-16T10:05:00+01:00", "direction": "outgoing",
    "counterpart": "+33639980003", "duration": 60},
   {"id": "r3", "category": "location", "timestamp": 1773655800, "latitude": 48.8566, "longitude": 2.3522,
    "location_kind": "estimated"}
 ]}
```

## CSV

Header must start with `category,timestamp`; recognised columns: `category, timestamp, direction,
counterpart (or counterparts separated by ; or |), name, body, duration, latitude, longitude,
conversation_id, location_kind, subtype, url, title`.

## Field rules

* `category`: contact, message, call, location, calendar, note, browser.
* `timestamp`: ISO-8601 (with offset preferably) or Unix epoch (s/ms/us/ns detected by magnitude).
  Naive values are interpreted in the case timezone and the assumption is recorded.
* `location_kind`: `recorded` (default) or `estimated`.
* The original record is kept verbatim as the artefact's raw values.
