"""Web browser artefacts: Chromium (Chrome, Edge, Samsung Internet, ...),
Safari and Firefox. Cookie values encrypted by the browser are never
decrypted; only metadata is reported."""
from __future__ import annotations

import json

from ..core.timeutils import from_mac_absolute, from_unix_micros, from_webkit_micros
from .base import Analyzer, ArtifactRecord, Category, row_dict, safe_cols


def _wk(v):
    return (from_webkit_micros(v), "webkit_us") if v else (None, None)


class ChromiumHistoryAnalyzer(Analyzer):
    name = "browser.chromium_history"
    version = "1.0"
    categories = (Category.BROWSER,)
    description = "Chromium-based browser history and downloads."
    sources = "History: urls, visits, downloads, downloads_url_chains"

    def matches(self, f):
        return f.has("urls", "url", "title", "last_visit_time") and f.has("visits", "url", "visit_time")

    def parse(self, f):
        con = f.connect()
        try:
            for r in con.execute("SELECT v.id AS vid, v.visit_time, v.transition, u.id AS uid, u.url, u.title, "
                                 "u.visit_count FROM visits v JOIN urls u ON u.id = v.url"):
                ts, m = _wk(r["visit_time"])
                yield ArtifactRecord(category=Category.BROWSER, subtype="history_visit", timestamp=ts,
                                     timestamp_raw=str(r["visit_time"]), timestamp_method=m,
                                     summary=f"Visit {r['title'] or ''} {r['url']}"[:400],
                                     source_table="visits", source_rowid=str(r["vid"]), raw=row_dict(r),
                                     interpreted={"url": r["url"], "title": r["title"],
                                                  "transition_core": (r["transition"] or 0) & 0xFF,
                                                  "visit_count": r["visit_count"]})
            if f.has("downloads", "id", "start_time"):
                cols = ", ".join(safe_cols(f, "downloads", ["id", "current_path", "target_path", "start_time",
                                                            "end_time", "received_bytes", "total_bytes", "state",
                                                            "mime_type", "tab_url", "referrer"]))
                chains = {}
                if f.has("downloads_url_chains", "id", "url"):
                    for c in con.execute("SELECT id, url FROM downloads_url_chains ORDER BY chain_index"):
                        chains.setdefault(c["id"], []).append(c["url"])
                for r in con.execute(f"SELECT {cols} FROM downloads"):
                    ts, m = _wk(r["start_time"])
                    url = (chains.get(r["id"]) or [r["tab_url"]])[-1]
                    yield ArtifactRecord(category=Category.BROWSER, subtype="download", timestamp=ts,
                                         timestamp_raw=str(r["start_time"]), timestamp_method=m,
                                         summary=f"Download {r['target_path'] or r['current_path']} from {url}"[:400],
                                         source_table="downloads", source_rowid=str(r["id"]), raw=row_dict(r),
                                         interpreted={"url": url, "path": r["target_path"] or r["current_path"],
                                                      "bytes": r["received_bytes"], "mime": r["mime_type"],
                                                      "url_chain": chains.get(r["id"], [])})
        finally:
            con.close()


class ChromiumCookiesAnalyzer(Analyzer):
    name = "browser.chromium_cookies"
    version = "1.0"
    categories = (Category.BROWSER,)
    description = "Chromium cookie metadata (encrypted values are not decrypted)."
    sources = "Cookies: cookies"

    def matches(self, f):
        return f.has("cookies", "host_key", "name", "creation_utc")

    def parse(self, f):
        con = f.connect()
        try:
            cols = ", ".join(safe_cols(f, "cookies", ["rowid", "host_key", "name", "path", "creation_utc",
                                                      "expires_utc", "last_access_utc", "value", "encrypted_value",
                                                      "is_secure", "is_httponly"]))
            for r in con.execute(f"SELECT {cols} FROM cookies"):
                ts, m = _wk(r["creation_utc"])
                enc = r["encrypted_value"]
                raw = row_dict(r)
                yield ArtifactRecord(category=Category.BROWSER, subtype="cookie", timestamp=ts,
                                     timestamp_raw=str(r["creation_utc"]), timestamp_method=m,
                                     summary=f"Cookie {r['name']} @ {r['host_key']}",
                                     source_table="cookies", source_rowid=str(r["rowid"]), raw=raw,
                                     interpreted={"host": r["host_key"], "name": r["name"],
                                                  "value_present": bool(r["value"]),
                                                  "value_encrypted": bool(enc),
                                                  "last_access": (_wk(r["last_access_utc"])[0] or None) and _wk(r["last_access_utc"])[0].isoformat(),
                                                  "note": "encrypted cookie values are not decrypted" if enc else None})
        finally:
            con.close()


class ChromiumBookmarksAnalyzer(Analyzer):
    name = "browser.chromium_bookmarks"
    version = "1.0"
    categories = (Category.BROWSER,)
    description = "Chromium 'Bookmarks' JSON file."
    sources = "Bookmarks (JSON with roots/bookmark_bar/other/synced)"

    def matches(self, f):
        if f.detected_type != "json" or f.size > 50 * 1024 * 1024:
            return False
        head = f.read_text(2048)
        return '"roots"' in head and ('"bookmark_bar"' in head or '"checksum"' in head)

    def parse(self, f):
        try:
            doc = json.loads(f.read_text())
        except json.JSONDecodeError:
            return

        def walk(node, folder):
            if node.get("type") == "url":
                v = node.get("date_added")
                ts, m = _wk(int(v)) if str(v or "").isdigit() and int(v) else (None, None)
                yield ArtifactRecord(category=Category.BROWSER, subtype="bookmark", timestamp=ts, timestamp_raw=v,
                                     timestamp_method=m, summary=f"Bookmark {node.get('name')} {node.get('url')}"[:400],
                                     source_table=folder, source_rowid=str(node.get("id")), raw=node,
                                     interpreted={"url": node.get("url"), "title": node.get("name"), "folder": folder})
            for child in node.get("children", []) or []:
                yield from walk(child, f"{folder}/{node.get('name', '')}")

        for key, root in (doc.get("roots") or {}).items():
            if isinstance(root, dict):
                yield from walk(root, key)


class SafariHistoryAnalyzer(Analyzer):
    name = "browser.safari_history"
    version = "1.0"
    categories = (Category.BROWSER,)
    description = "Safari History.db (iOS / macOS)."
    sources = "History.db: history_items, history_visits"

    def matches(self, f):
        return f.has("history_items", "id", "url") and f.has("history_visits", "history_item", "visit_time")

    def parse(self, f):
        con = f.connect()
        try:
            for r in con.execute("SELECT v.id AS vid, v.visit_time, v.title, i.url, i.visit_count FROM history_visits v "
                                 "JOIN history_items i ON i.id = v.history_item"):
                ts, m = from_mac_absolute(r["visit_time"]) if r["visit_time"] else (None, None)
                yield ArtifactRecord(category=Category.BROWSER, subtype="history_visit", timestamp=ts,
                                     timestamp_raw=str(r["visit_time"]), timestamp_method=m,
                                     summary=f"Visit {r['title'] or ''} {r['url']}"[:400], source_table="history_visits",
                                     source_rowid=str(r["vid"]), raw=row_dict(r),
                                     interpreted={"url": r["url"], "title": r["title"], "visit_count": r["visit_count"]})
        finally:
            con.close()


class FirefoxPlacesAnalyzer(Analyzer):
    name = "browser.firefox_places"
    version = "1.0"
    categories = (Category.BROWSER,)
    description = "Firefox / Firefox for Android (Fenix) places.sqlite history and bookmarks."
    sources = "places.sqlite: moz_places, moz_historyvisits, moz_bookmarks"

    def matches(self, f):
        return f.has("moz_places", "id", "url") and f.has("moz_historyvisits", "place_id", "visit_date")

    def parse(self, f):
        con = f.connect()
        try:
            for r in con.execute("SELECT v.id AS vid, v.visit_date, v.visit_type, p.url, p.title FROM moz_historyvisits v "
                                 "JOIN moz_places p ON p.id = v.place_id"):
                ts = from_unix_micros(r["visit_date"]) if r["visit_date"] else None
                yield ArtifactRecord(category=Category.BROWSER, subtype="history_visit", timestamp=ts,
                                     timestamp_raw=str(r["visit_date"]), timestamp_method="unix_us",
                                     summary=f"Visit {r['title'] or ''} {r['url']}"[:400], source_table="moz_historyvisits",
                                     source_rowid=str(r["vid"]), raw=row_dict(r),
                                     interpreted={"url": r["url"], "title": r["title"], "visit_type": r["visit_type"]})
            if f.has("moz_bookmarks", "fk", "title", "dateadded"):
                for r in con.execute("SELECT b.id, b.title, b.dateAdded, p.url FROM moz_bookmarks b "
                                     "JOIN moz_places p ON p.id = b.fk WHERE b.type = 1"):
                    ts = from_unix_micros(r["dateAdded"]) if r["dateAdded"] else None
                    yield ArtifactRecord(category=Category.BROWSER, subtype="bookmark", timestamp=ts,
                                         timestamp_raw=str(r["dateAdded"]), timestamp_method="unix_us",
                                         summary=f"Bookmark {r['title'] or ''} {r['url']}"[:400], source_table="moz_bookmarks",
                                         source_rowid=str(r["id"]), raw=row_dict(r),
                                         interpreted={"url": r["url"], "title": r["title"]})
        finally:
            con.close()


ANALYZERS = [ChromiumHistoryAnalyzer(), ChromiumCookiesAnalyzer(), ChromiumBookmarksAnalyzer(),
             SafariHistoryAnalyzer(), FirefoxPlacesAnalyzer()]
