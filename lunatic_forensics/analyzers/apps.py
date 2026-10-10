"""Application artefact inventory.

Detects applications from paths inside the evidence (adb backup ``apps/<pkg>``,
``data/data/<pkg>``, ``Android/data/<pkg>``, iOS ``AppDomain-<bundle>``),
lists their databases and states whether a tested adapter exists.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .base import ArtifactRecord, Category, FileContext

PATTERNS = [
    re.compile(r"(?:^|/)apps/([A-Za-z][\w]*(?:\.[\w]+)+)/"),
    re.compile(r"(?:^|/)data/data/([A-Za-z][\w]*(?:\.[\w]+)+)/"),
    re.compile(r"(?:^|/)data/user/\d+/([A-Za-z][\w]*(?:\.[\w]+)+)/"),
    re.compile(r"(?:^|/)Android/(?:data|media|obb)/([A-Za-z][\w]*(?:\.[\w]+)+)/"),
    re.compile(r"^AppDomain(?:Group|Plugin)?-([\w.\-]+)/"),
]

KNOWN_APPS = {
    "com.whatsapp": ("WhatsApp", "supported for decrypted msgstore.db (messaging.whatsapp_android); "
                                 "msgstore.db.crypt14/15 are end-to-end-backup encrypted and NOT decrypted"),
    "com.whatsapp.w4b": ("WhatsApp Business", "same as WhatsApp"),
    "net.whatsapp.WhatsApp": ("WhatsApp (iOS)", "supported: ChatStorage.sqlite (messaging.whatsapp_ios)"),
    "group.net.whatsapp.WhatsApp.shared": ("WhatsApp (iOS shared group)", "supported: ChatStorage.sqlite"),
    "org.telegram.messenger": ("Telegram", "not supported: TL-serialised blobs in cache4.db"),
    "ph.telegra.Telegraph": ("Telegram (iOS)", "not supported: proprietary Postbox storage"),
    "org.thoughtcrime.securesms": ("Signal", "not supported: SQLCipher database, key protected by Android Keystore"),
    "org.whispersystems.signal": ("Signal (iOS)", "not supported: encrypted database"),
    "com.facebook.orca": ("Messenger", "no adapter yet"),
    "com.instagram.android": ("Instagram", "no adapter yet"),
    "com.snapchat.android": ("Snapchat", "no adapter yet"),
    "com.viber.voip": ("Viber", "no adapter yet"),
    "com.skype.raider": ("Skype", "no adapter yet"),
    "com.android.chrome": ("Chrome", "supported: History, Cookies (metadata), Bookmarks"),
    "com.sec.android.app.sbrowser": ("Samsung Internet", "supported: Chromium History"),
    "org.mozilla.firefox": ("Firefox", "supported: places.sqlite"),
    "com.android.providers.telephony": ("Telephony provider", "supported: mmssms.db"),
    "com.android.providers.contacts": ("Contacts provider", "supported: contacts2.db / calllog.db"),
    "com.android.providers.calendar": ("Calendar provider", "supported: calendar.db"),
    "com.google.android.apps.maps": ("Google Maps", "no adapter yet"),
}


def package_from_path(path: str) -> str | None:
    for rx in PATTERNS:
        m = rx.search(path)
        if m:
            return m.group(1)
    return None


def inventory_apps(entries: list[tuple[FileContext, list[str]]]):
    apps: dict[str, dict] = defaultdict(lambda: {"files": 0, "bytes": 0, "databases": [], "parsed_by": set(),
                                                 "unparsed_databases": [], "encrypted_candidates": []})
    for f, matched in entries:
        pkg = package_from_path(f.logical_path)
        if not pkg:
            continue
        a = apps[pkg]
        a["files"] += 1
        a["bytes"] += f.size
        if f.detected_type == "sqlite":
            a["databases"].append(f.logical_path)
            specific = [m for m in matched if not m.startswith(("recovery.", "documents."))]
            a["parsed_by"].update(specific)
            if not specific:
                a["unparsed_databases"].append(f.logical_path)
        elif re.search(r"\.crypt\d+$", f.name) or f.name.endswith((".db", ".sqlite")) and f.detected_type == "binary":
            a["encrypted_candidates"].append(f.logical_path)
    for pkg, a in sorted(apps.items()):
        name, support = KNOWN_APPS.get(pkg, (pkg, "no specific adapter: databases inventoried only"))
        yield ArtifactRecord(
            category=Category.APP, subtype="app_data", summary=f"App {name} ({pkg}): {a['files']} files, "
                                                               f"{len(a['databases'])} databases",
            source_table="inventory", source_rowid=pkg,
            raw={"package": pkg, "files": a["files"], "bytes": a["bytes"]},
            interpreted={"package": pkg, "name": name, "support": support, "databases": a["databases"][:200],
                         "parsed_by": sorted(a["parsed_by"]), "unparsed_databases": a["unparsed_databases"][:200],
                         "encrypted_or_unreadable": a["encrypted_candidates"][:200]})
