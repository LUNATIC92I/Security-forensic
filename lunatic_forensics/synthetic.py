"""Synthetic test data generator.

**Everything produced here is fictitious.** Phone numbers use the French range
reserved for fiction (+33 6 39 98 xx xx), e-mails use the reserved
``example.org`` domain and names are invented. The files mimic the documented
schemas of the formats supported by the analyzers so that parsers, imports and
reports can be validated without any real personal data.
"""
from __future__ import annotations

import gzip
import io
import json
import plistlib
import sqlite3
import struct
import tarfile
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
BASE = datetime(2026, 3, 14, 8, 0, 0, tzinfo=UTC)
MAC_OFFSET = 978307200
WEBKIT_OFFSET = 11644473600

OWNER = ("Alex Martin (synthetic)", "+33639980000")
BOB = ("Bob Durand", "+33639980001", "bob.durand@example.org")
CLAIRE = ("Claire Petit", "+33639980002", "claire.petit@example.org")
DAN = ("Dan Lefevre", "+33639980003", "dan.lefevre@example.org")

# (minutes after BASE, counterpart, direction, body)
CONVERSATION = [
    (0, BOB, "incoming", "Salut Alex, on se voit toujours demain ?"),
    (3, BOB, "outgoing", "Oui, 10h devant la gare."),
    (65, CLAIRE, "incoming", "Tu as recu le document ?"),
    (70, CLAIRE, "outgoing", "Pas encore, je regarde ce soir."),
    (1440 + 120, BOB, "incoming", "Je suis en retard de 10 minutes."),
    (1440 + 125, BOB, "outgoing", "Pas de souci."),
    (2880 + 30, DAN, "incoming", "Reunion deplacee a jeudi."),
]
# (minutes, counterpart, android type, duration)
CALLS = [(10, BOB, 1, 125), (75, CLAIRE, 2, 42), (1440 + 118, BOB, 3, 0), (2880 + 600, DAN, 2, 300)]


def ms(minutes: float) -> int:
    return int((BASE + timedelta(minutes=minutes)).timestamp() * 1000)


def mac_s(minutes: float) -> float:
    return (BASE + timedelta(minutes=minutes)).timestamp() - MAC_OFFSET


def mac_ns(minutes: float) -> int:
    return int(mac_s(minutes) * 1_000_000_000)


def webkit(minutes: float) -> int:
    return int(((BASE + timedelta(minutes=minutes)).timestamp() + WEBKIT_OFFSET) * 1_000_000)


def _db(path: Path, script: str, rows: dict[str, list[tuple]] | None = None, secure_delete: bool = True) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    con.execute(f"PRAGMA secure_delete={'ON' if secure_delete else 'OFF'}")
    con.executescript(script)
    for table, data in (rows or {}).items():
        if data:
            con.executemany(f"INSERT INTO {table} VALUES ({','.join('?' * len(data[0]))})", data)
    con.commit()
    con.close()
    return path


# ------------------------------------------------------------------ Android
def android_mmssms(path: Path) -> Path:
    rows = []
    for i, (m, who, d, body) in enumerate(CONVERSATION, 1):
        thread = {BOB: 1, CLAIRE: 2, DAN: 3}[who]
        addr = who[1].replace("+33", "0") if i % 2 else who[1]  # mix national / international formats
        rows.append((i, thread, addr, None, ms(m), ms(m) - 2000, 1, -1, 1 if d == "incoming" else 2, None, body, None))
    p = _db(path, """
        CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, person INTEGER, date INTEGER,
            date_sent INTEGER, read INTEGER, status INTEGER, type INTEGER, subject TEXT, body TEXT, service_center TEXT);
        CREATE TABLE pdu (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, msg_box INTEGER, sub TEXT);
        CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER, ct TEXT, text TEXT, _data TEXT);
        CREATE TABLE addr (_id INTEGER PRIMARY KEY, msg_id INTEGER, address TEXT, type INTEGER);
        CREATE TABLE threads (_id INTEGER PRIMARY KEY, recipient_ids TEXT);
    """, {"sms": rows,
          "pdu": [(1, 2, ms(200) // 1000, 1, None)],
          "part": [(1, 1, "application/smil", None, None), (2, 1, "text/plain", "Voici la photo du document", None),
                   (3, 1, "image/jpeg", None, "/data/user_de/0/com.android.providers.telephony/app_parts/PART_1.jpg")],
          "addr": [(1, 1, CLAIRE[1], 137), (2, 1, OWNER[1], 151)]})
    return p


def android_contacts2(path: Path) -> Path:
    contacts = [BOB, CLAIRE, DAN]
    mimetypes = [(1, "vnd.android.cursor.item/name"), (2, "vnd.android.cursor.item/phone_v2"),
                 (3, "vnd.android.cursor.item/email_v2"), (4, "vnd.android.cursor.item/organization")]
    raws, data = [], []
    did = 1
    for i, (name, phone, email) in enumerate(contacts, 1):
        raws.append((i, i, name, 0, "com.google", "owner@example.org", 3, ms(-1000)))
        data += [(did, i, 1, name, name.split()[0], name.split()[1], None),
                 (did + 1, i, 2, phone.replace("+33", "0"), "2", None, phone),
                 (did + 2, i, 3, email, "1", None, None)]
        did += 3
    # duplicate entry of Bob (other account) to test duplicate detection
    raws.append((4, 1, BOB[0], 0, "com.whatsapp", BOB[1], 0, None))
    data += [(did, 4, 1, BOB[0], None, None, None), (did + 1, 4, 2, BOB[1], "2", None, BOB[1])]
    return _db(path, """
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, contact_id INTEGER, display_name TEXT, deleted INTEGER,
            account_type TEXT, account_name TEXT, times_contacted INTEGER, last_time_contacted INTEGER);
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER, data1 TEXT,
            data2 TEXT, data3 TEXT, data4 TEXT);
    """, {"raw_contacts": raws, "mimetypes": mimetypes, "data": data})


def android_calllog(path: Path) -> Path:
    rows = [(i, who[1], ms(m), dur, t, who[0], "FR", "France", 1, 0) for i, (m, who, t, dur) in enumerate(CALLS, 1)]
    return _db(path, """CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER,
        type INTEGER, name TEXT, countryiso TEXT, geocoded_location TEXT, presentation INTEGER, subscription_id INTEGER);""",
               {"calls": rows})


def android_calendar(path: Path) -> Path:
    return _db(path, """
        CREATE TABLE Calendars (_id INTEGER PRIMARY KEY, calendar_displayName TEXT, account_name TEXT);
        CREATE TABLE Events (_id INTEGER PRIMARY KEY, calendar_id INTEGER, title TEXT, eventLocation TEXT,
            description TEXT, dtstart INTEGER, dtend INTEGER, eventTimezone TEXT, deleted INTEGER);
    """, {"Calendars": [(1, "Personnel", "owner@example.org")],
          "Events": [(1, 1, "Rendez-vous gare", "Gare de Lyon, Paris", "Avec Bob", ms(1440 + 120), ms(1440 + 180),
                      "Europe/Paris", 0),
                     (2, 1, "Reunion projet", "Bureau", "Deplacee", ms(4320), ms(4380), "Europe/Paris", 0)]})


def adb_getprop(path: Path) -> Path:
    props = {"ro.product.manufacturer": "SyntheticMobile", "ro.product.model": "SM-TEST1",
             "ro.build.version.release": "14", "ro.build.version.sdk": "34",
             "ro.build.version.security_patch": "2026-02-01", "ro.serialno": "SYNTH0001",
             "ro.crypto.state": "encrypted", "ro.crypto.type": "file", "persist.sys.timezone": "Europe/Paris"}
    Path(path).write_text("\n".join(f"[{k}]: [{v}]" for k, v in props.items()) + "\n")
    return Path(path)


def adb_packages(path: Path) -> Path:
    Path(path).write_text("package:/data/app/~~x/com.whatsapp-1/base.apk=com.whatsapp\n"
                          "package:/system/app/Chrome/Chrome.apk=com.android.chrome\n"
                          "package:/data/app/~~y/org.example.notes-2/base.apk=org.example.notes\n")
    return Path(path)


SYNTH_BACKUP_PASSWORD = "Synthetic!Backup-2026"


def _ab_encrypt(payload: bytes, password: str, version: int = 5, rounds: int = 10000) -> bytes:
    """Encrypt an adb backup payload following the AOSP format (see ingest/plugins/android_backup.py)."""
    import hashlib
    import os as _os

    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from .ingest.plugins.android_backup import mangle_key

    def enc(key, iv, data):
        p = padding.PKCS7(128).padder()
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return e.update(p.update(data) + p.finalize()) + e.finalize()

    user_salt, ck_salt, user_iv = _os.urandom(64), _os.urandom(64), _os.urandom(16)
    master_key, master_iv = _os.urandom(32), _os.urandom(16)
    master_key = b"\x80\xff" + master_key[2:]  # exercise the Java signed-byte checksum mangling
    user_key = hashlib.pbkdf2_hmac("sha1", password.encode(), user_salt, rounds, 32)
    checksum = hashlib.pbkdf2_hmac("sha1", mangle_key(master_key, version), ck_salt, rounds, 32)
    blob = bytes([16]) + master_iv + bytes([32]) + master_key + bytes([32]) + checksum
    hdr = (f"{user_salt.hex().upper()}\n{ck_salt.hex().upper()}\n{rounds}\n{user_iv.hex().upper()}\n"
           f"{enc(user_key, user_iv, blob).hex().upper()}\n").encode()
    return hdr + enc(master_key, master_iv, payload)


def android_backup(path: Path, compressed: bool = True, encrypted: bool = False,
                   password: str = SYNTH_BACKUP_PASSWORD) -> Path:
    """Build an adb backup (.ab) containing telephony and contacts databases.

    With ``encrypted=True`` the payload is genuinely AES-256 encrypted with ``password``."""
    tmp = Path(path).with_suffix(".tmpdir")
    tmp.mkdir(parents=True, exist_ok=True)
    sms = android_mmssms(tmp / "mmssms.db")
    contacts = android_contacts2(tmp / "contacts2.db")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(sms, arcname="apps/com.android.providers.telephony/db/mmssms.db")
        tf.add(contacts, arcname="apps/com.android.providers.contacts/db/contacts2.db")
        info = tarfile.TarInfo("apps/com.android.providers.contacts/_manifest")
        payload = b"6\ncom.android.providers.contacts\n"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    data = zlib.compress(buf.getvalue()) if compressed else buf.getvalue()
    header = f"ANDROID BACKUP\n5\n{1 if compressed else 0}\n{'AES-256' if encrypted else 'none'}\n".encode()
    Path(path).write_bytes(header + (_ab_encrypt(data, password) if encrypted else data))
    for p in tmp.iterdir():
        p.unlink()
    tmp.rmdir()
    return Path(path)


# ---------------------------------------------------------------------- iOS
def _typedstream(text: str) -> bytes:
    b = text.encode()
    length = bytes([len(b)]) if len(b) < 0x80 else b"\x81" + len(b).to_bytes(2, "little")
    return b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x12NSAttributedString\x00\x84\x84\x08NSObject" \
           b"\x00\x85\x92\x84\x84\x84\x08NSString\x01\x94\x84\x01+" + length + b + b"\x86\x84\x02iI\x01"


def ios_sms(path: Path) -> Path:
    handles = {BOB: 1, CLAIRE: 2, DAN: 3}
    msgs, joins = [], []
    for i, (m, who, d, body) in enumerate(CONVERSATION, 1):
        service = "iMessage" if who == BOB else "SMS"
        text, attributed = (body, None) if i != 2 else (None, _typedstream(body))  # iOS16+ style body for one message
        msgs.append((i, f"GUID-{i}", text, handles[who], service, mac_ns(m), mac_ns(m + 1) if d == "incoming" else 0, 0,
                     1 if d == "outgoing" else 0, attributed, 0, 1))
        joins.append((handles[who], i))
    return _db(path, """
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, handle_id INTEGER, service TEXT, date INTEGER,
            date_read INTEGER, date_delivered INTEGER, is_from_me INTEGER, attributedBody BLOB,
            cache_has_attachments INTEGER, is_read INTEGER);
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT, service TEXT);
        CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, chat_identifier TEXT, display_name TEXT, guid TEXT);
        CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
        CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY, filename TEXT, mime_type TEXT, transfer_name TEXT, total_bytes INTEGER);
        CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);
    """, {"message": msgs,
          "handle": [(1, BOB[1], "iMessage"), (2, CLAIRE[1], "SMS"), (3, DAN[2], "iMessage")],
          "chat": [(1, BOB[1], None, "iMessage;-;" + BOB[1]), (2, CLAIRE[1], None, "SMS;-;" + CLAIRE[1]),
                   (3, DAN[2], None, "iMessage;-;" + DAN[2])],
          "chat_message_join": joins,
          "attachment": [(1, "~/Library/SMS/Attachments/aa/IMG_0001.jpeg", "image/jpeg", "IMG_0001.jpeg", 2048)],
          "message_attachment_join": [(3, 1)]})


def ios_addressbook(path: Path) -> Path:
    persons, mvs = [], []
    for i, (name, phone, email) in enumerate([BOB, CLAIRE, DAN], 1):
        first, last = name.split()
        persons.append((i, first, last, None, None, None, None, mac_s(-5000), mac_s(-100)))
        national = f"0{phone[3]} {phone[4:6]} {phone[6:8]} {phone[8:10]} {phone[10:12]}"
        mvs += [(len(mvs) + 1, i, 3, 1, national if i == 2 else phone),
                (len(mvs) + 2, i, 4, 2, email)]
    return _db(path, """
        CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY, First TEXT, Last TEXT, Middle TEXT, Organization TEXT,
            Nickname TEXT, Note TEXT, CreationDate REAL, ModificationDate REAL);
        CREATE TABLE ABMultiValue (UID INTEGER PRIMARY KEY, record_id INTEGER, property INTEGER, label INTEGER, value TEXT);
    """, {"ABPerson": persons, "ABMultiValue": mvs})


def ios_callhistory(path: Path) -> Path:
    rows = []
    for i, (m, who, t, dur) in enumerate(CALLS, 1):
        rows.append((i, who[1], mac_s(m), float(dur), 1 if t == 2 else 0, 1 if t in (1, 2) else 0, 1 if i != 2 else 16,
                     None, "com.apple.Telephony" if i != 2 else "com.apple.FaceTime", "fr", None))
    return _db(path, """CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS TEXT, ZDATE REAL, ZDURATION REAL,
        ZORIGINATED INTEGER, ZANSWERED INTEGER, ZCALLTYPE INTEGER, ZNAME TEXT, ZSERVICE_PROVIDER TEXT,
        ZISO_COUNTRY_CODE TEXT, ZLOCATION TEXT);""", {"ZCALLRECORD": rows})


def ios_calendar(path: Path) -> Path:
    return _db(path, """
        CREATE TABLE CalendarItem (ROWID INTEGER PRIMARY KEY, summary TEXT, start_date REAL, end_date REAL,
            location_id INTEGER, description TEXT, start_tz TEXT);
        CREATE TABLE Location (ROWID INTEGER PRIMARY KEY, title TEXT);
    """, {"CalendarItem": [(1, "Dejeuner Claire", mac_s(1440 + 240), mac_s(1440 + 300), 1, "", "Europe/Paris")],
          "Location": [(1, "Cafe synthetique, Paris")]})


def _pb_len(field: int, payload: bytes) -> bytes:
    def varint(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                return out
    return varint(field << 3 | 2) + varint(len(payload)) + payload


def ios_notestore(path: Path) -> Path:
    note = _pb_len(2, "Liste: acheter carte SIM, appeler Bob".encode())
    doc = _pb_len(3, note)
    proto = _pb_len(2, doc)
    data = gzip.compress(proto)
    return _db(path, """
        CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, ZTITLE1 TEXT, ZCREATIONDATE1 REAL,
            ZMODIFICATIONDATE1 REAL, ZISPASSWORDPROTECTED INTEGER);
        CREATE TABLE ZICNOTEDATA (Z_PK INTEGER PRIMARY KEY, ZNOTE INTEGER, ZDATA BLOB);
    """, {"ZICCLOUDSYNCINGOBJECT": [(1, "Courses", mac_s(30), mac_s(40), 0), (2, "Prive", mac_s(50), mac_s(55), 1)],
          "ZICNOTEDATA": [(1, 1, data), (2, 2, b"\x00encrypted")]})


def ios_photos(path: Path) -> Path:
    return _db(path, """CREATE TABLE ZASSET (Z_PK INTEGER PRIMARY KEY, ZDIRECTORY TEXT, ZFILENAME TEXT, ZDATECREATED REAL,
        ZLATITUDE REAL, ZLONGITUDE REAL, ZTRASHEDSTATE INTEGER, ZKIND INTEGER);""",
               {"ZASSET": [(1, "DCIM/100APPLE", "IMG_0001.HEIC", mac_s(1440 + 115), 48.84434, 2.37386, 0, 0),
                           (2, "DCIM/100APPLE", "IMG_0002.HEIC", mac_s(1440 + 500), -180.0, -180.0, 1, 0)]})


def ios_backup(dest: Path, encrypted: bool = False) -> Path:
    """Unencrypted iOS backup folder layout (Manifest.db + hashed files)."""
    import hashlib
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    files = [("HomeDomain", "Library/SMS/sms.db", ios_sms),
             ("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", ios_addressbook),
             ("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata", ios_callhistory),
             ("HomeDomain", "Library/Calendar/Calendar.sqlitedb", ios_calendar),
             ("AppDomainGroup-group.com.apple.notes", "NoteStore.sqlite", ios_notestore),
             ("CameraRollDomain", "Media/PhotoData/Photos.sqlite", ios_photos)]
    rows = []
    for domain, rel, fn in files:
        fid = hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()
        fn(dest / fid[:2] / fid)
        rows.append((fid, domain, rel, 1, None))
    rows.append(("0" * 40, "HomeDomain", "Library/SMS", 2, None))  # directory entry
    _db(dest / "Manifest.db", "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);",
        {"Files": rows})
    with open(dest / "Info.plist", "wb") as f:
        plistlib.dump({"Device Name": "iPhone synthetique", "Product Type": "iPhone15,2", "Product Version": "17.4",
                       "Build Version": "21E219", "Serial Number": "SYNTHSERIAL01", "Unique Identifier": "0" * 40,
                       "Phone Number": OWNER[1], "Last Backup Date": BASE + timedelta(days=3)}, f)
    with open(dest / "Manifest.plist", "wb") as f:
        plistlib.dump({"IsEncrypted": encrypted, "Version": "10.0", "Date": BASE + timedelta(days=3),
                       "Lockdown": {"ProductVersion": "17.4", "DeviceName": "iPhone synthetique"}}, f)
    with open(dest / "Status.plist", "wb") as f:
        plistlib.dump({"IsFullBackup": True, "SnapshotState": "finished"}, f)
    return dest


# ---------------------------------------------------------------- messaging
def whatsapp_android_legacy(path: Path) -> Path:
    rows = [(1, BOB[1][1:] + "@s.whatsapp.net", 0, "K1", "On part a 9h45 ?", ms(1440 + 60), None, None, 0.0, 0.0, None, 13),
            (2, BOB[1][1:] + "@s.whatsapp.net", 1, "K2", "OK", ms(1440 + 61), None, None, 0.0, 0.0, None, 13),
            (3, "120363000000000000@g.us", 0, "K3", "Bienvenue dans le groupe", ms(1440 + 90), None, None, 0.0, 0.0,
             CLAIRE[1][1:] + "@s.whatsapp.net", 13),
            (4, BOB[1][1:] + "@s.whatsapp.net", 0, "K4", None, ms(1440 + 116), "image/jpeg", "IMG-WA0001.jpg",
             48.8443, 2.3739, None, 13)]
    return _db(path, """CREATE TABLE messages (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, key_from_me INTEGER, key_id TEXT,
        data TEXT, timestamp INTEGER, media_mime_type TEXT, media_name TEXT, latitude REAL, longitude REAL,
        remote_resource TEXT, status INTEGER);""", {"messages": rows})


def whatsapp_android_modern(path: Path) -> Path:
    return _db(path, """
        CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT, raw_string TEXT);
        CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);
        CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, key_id TEXT,
            sender_jid_row_id INTEGER, timestamp INTEGER, text_data TEXT, message_type INTEGER, status INTEGER);
        CREATE TABLE message_media (message_row_id INTEGER, mime_type TEXT, file_path TEXT);
        CREATE TABLE message_location (message_row_id INTEGER, latitude REAL, longitude REAL);
    """, {"jid": [(1, CLAIRE[1][1:], "s.whatsapp.net", CLAIRE[1][1:] + "@s.whatsapp.net")],
          "chat": [(1, 1, None)],
          "message": [(1, 1, 0, "M1", None, ms(1440 + 300), "Je t'envoie ma position", 0, 13),
                      (2, 1, 0, "M2", None, ms(1440 + 301), None, 5, 13)],
          "message_location": [(2, 48.8530, 2.3499)]})


def whatsapp_ios(path: Path) -> Path:
    return _db(path, """
        CREATE TABLE ZWACHATSESSION (Z_PK INTEGER PRIMARY KEY, ZCONTACTJID TEXT, ZPARTNERNAME TEXT);
        CREATE TABLE ZWAMESSAGE (Z_PK INTEGER PRIMARY KEY, ZISFROMME INTEGER, ZFROMJID TEXT, ZTOJID TEXT, ZTEXT TEXT,
            ZMESSAGEDATE REAL, ZCHATSESSION INTEGER, ZMESSAGETYPE INTEGER, ZPUSHNAME TEXT);
        CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER PRIMARY KEY, ZMESSAGE INTEGER, ZMEDIALOCALPATH TEXT, ZLATITUDE REAL, ZLONGITUDE REAL);
    """, {"ZWACHATSESSION": [(1, DAN[1][1:] + "@s.whatsapp.net", "Dan")],
          "ZWAMESSAGE": [(1, 0, DAN[1][1:] + "@s.whatsapp.net", None, "Tu as le dossier ?", mac_s(2880 + 40), 1, 0, "Dan"),
                         (2, 1, None, DAN[1][1:] + "@s.whatsapp.net", "Oui je l'apporte", mac_s(2880 + 45), 1, 0, None)],
          "ZWAMEDIAITEM": []})


def sms_backup_restore_xml(path: Path) -> Path:
    items = "".join(
        f'<sms protocol="0" address="{who[1]}" date="{ms(m)}" type="{1 if d == "incoming" else 2}" subject="null" '
        f'body="{body}" read="1" contact_name="{who[0]}" />' for m, who, d, body in CONVERSATION[:3])
    Path(path).write_text(f'<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>\n<smses count="3">{items}</smses>\n',
                          encoding="utf-8")
    return Path(path)


# ------------------------------------------------------------------ browser
def chrome_history(path: Path) -> Path:
    return _db(path, """
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT, start_time INTEGER,
            end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, mime_type TEXT, tab_url TEXT);
        CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
    """, {"urls": [(1, "https://www.example.org/horaires-trains", "Horaires trains", 2, webkit(20)),
                   (2, "https://maps.example.org/?q=gare", "Carte", 1, webkit(1440 + 100))],
          "visits": [(1, 1, webkit(15), 0, 805306368), (2, 1, webkit(20), 1, 805306376), (3, 2, webkit(1440 + 100), 0, 1)],
          "downloads": [(1, "/storage/emulated/0/Download/dossier.pdf", "/storage/emulated/0/Download/dossier.pdf",
                         webkit(80), webkit(81), 3500, 3500, 1, "application/pdf", "https://files.example.org/dossier.pdf")],
          "downloads_url_chains": [(1, 0, "https://files.example.org/dossier.pdf")]})


def chrome_cookies(path: Path) -> Path:
    return _db(path, """CREATE TABLE cookies (creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, path TEXT,
        expires_utc INTEGER, last_access_utc INTEGER, encrypted_value BLOB, is_secure INTEGER, is_httponly INTEGER);""",
               {"cookies": [(webkit(15), ".example.org", "session", "", "/", webkit(99999), webkit(20), b"v10\x01\x02\x03", 1, 1)]})


def chrome_bookmarks(path: Path) -> Path:
    doc = {"checksum": "0", "version": 1, "roots": {
        "bookmark_bar": {"type": "folder", "name": "Barre", "children": [
            {"type": "url", "name": "Banque synthetique", "url": "https://bank.example.org/", "id": "5",
             "date_added": str(webkit(-2000))}]},
        "other": {"type": "folder", "name": "Autres", "children": []}}}
    Path(path).write_text(json.dumps(doc))
    return Path(path)


def safari_history(path: Path) -> Path:
    return _db(path, """
        CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
        CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);
    """, {"history_items": [(1, "https://news.example.org/", 1)], "history_visits": [(1, 1, mac_s(500), "Actualites")]})


def firefox_places(path: Path) -> Path:
    us = lambda m: ms(m) * 1000  # noqa: E731
    return _db(path, """
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
        CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, title TEXT, dateAdded INTEGER);
    """, {"moz_places": [(1, "https://wiki.example.org/Paris", "Paris", 1, us(700))],
          "moz_historyvisits": [(1, 1, us(700), 1)], "moz_bookmarks": [(1, 1, 1, "Paris", us(701))]})


# -------------------------------------------------------------------- media
def jpeg_with_gps(path: Path, lat=48.844340, lon=2.373860, when: datetime | None = None, model="SM-TEST1") -> Path:
    from PIL import Image
    when = when or BASE + timedelta(minutes=1440 + 115, hours=1)  # local Paris time (UTC+1) written in EXIF
    img = Image.new("RGB", (64, 48), (30, 90, 200))
    exif = Image.Exif()
    exif[271] = "SyntheticMobile"
    exif[272] = model
    exif[306] = when.strftime("%Y:%m:%d %H:%M:%S")
    ifd = exif.get_ifd(0x8769)
    ifd[36867] = when.strftime("%Y:%m:%d %H:%M:%S")
    ifd[36881] = "+01:00"

    def dms(v):
        v = abs(v)
        d = int(v)
        m = int((v - d) * 60)
        s = round(((v - d) * 60 - m) * 60, 4)
        from PIL.TiffImagePlugin import IFDRational
        return (IFDRational(d, 1), IFDRational(m, 1), IFDRational(int(s * 10000), 10000))
    gps = exif.get_ifd(0x8825)
    gps[1] = "N" if lat >= 0 else "S"
    gps[2] = dms(lat)
    gps[3] = "E" if lon >= 0 else "W"
    gps[4] = dms(lon)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    img.save(path, "JPEG", exif=exif)
    return Path(path)


def png_plain(path: Path) -> Path:
    from PIL import Image
    Image.new("RGB", (16, 16), (200, 30, 30)).save(path, "PNG")
    return Path(path)


def _box(typ: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def mp4_with_location(path: Path) -> Path:
    ctime = int((BASE + timedelta(minutes=1440 + 130)).timestamp()) + 2082844800
    mvhd = _box(b"mvhd", b"\x00\x00\x00\x00" + struct.pack(">IIII", ctime, ctime, 1000, 12500) + b"\x00" * 80)
    xyz = _box(b"\xa9xyz", struct.pack(">HH", 18, 0x15c7) + b"+48.8443+002.3739/")
    moov = _box(b"moov", mvhd + _box(b"udta", xyz))
    ftyp = _box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2mp41")
    Path(path).write_bytes(ftyp + moov + _box(b"mdat", b"\x00" * 64))
    return Path(path)


# ---------------------------------------------------------------- documents
def docx(path: Path) -> Path:
    core = ('<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/'
            'package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:dcterms="http://purl.org/dc/terms/"><dc:title>Plan de rendez-vous</dc:title>'
            '<dc:creator>Claire Petit</dc:creator><cp:lastModifiedBy>Alex Martin</cp:lastModifiedBy>'
            '<dcterms:created>2026-03-13T17:00:00Z</dcterms:created><dcterms:modified>2026-03-14T09:00:00Z</dcterms:modified>'
            '</cp:coreProperties>')
    doc = ('<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/'
           '2006/main"><w:body><w:p><w:r><w:t>Rendez-vous a la gare a 10h.</w:t></w:r></w:p>'
           '<w:p><w:r><w:t>Apporter le dossier.</w:t></w:r></w:p></w:body></w:document>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("docProps/core.xml", core)
        z.writestr("word/document.xml", doc)
    return Path(path)


def pdf(path: Path) -> Path:
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
            b"<< /Title (Dossier synthetique) /Author (Claire Petit) /Producer (SynthPDF 1.0) "
            b"/CreationDate (D:20260313180000+01'00') >>"]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R /Info 4 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    Path(path).write_bytes(bytes(out))
    return Path(path)


# ------------------------------------------------------------ text exports
def vcard(path: Path) -> Path:
    Path(path).write_text("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Claire Petit\r\nN:Petit;Claire;;;\r\n"
                          f"TEL;TYPE=CELL:{CLAIRE[1]}\r\nEMAIL:{CLAIRE[2]}\r\nORG:Synthetic Org\r\nEND:VCARD\r\n"
                          "BEGIN:VCARD\r\nVERSION:2.1\r\nN;ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:Lef=C3=A8vre;Dan\r\n"
                          f"TEL;CELL:{DAN[1]}\r\nEND:VCARD\r\n", encoding="utf-8", newline="")
    return Path(path)


def icalendar(path: Path) -> Path:
    Path(path).write_text("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:evt-1@example.org\r\n"
                          "DTSTART;TZID=Europe/Paris:20260316T090000\r\nDTEND;TZID=Europe/Paris:20260316T100000\r\n"
                          "SUMMARY:Reunion projet\r\nLOCATION:Salle 2\r\nDESCRIPTION:Ordre du jour\\, budget\r\nEND:VEVENT\r\n"
                          "BEGIN:VTODO\r\nUID:todo-1@example.org\r\nDUE:20260317T120000Z\r\nSUMMARY:Rendre le dossier\r\n"
                          "END:VTODO\r\nEND:VCALENDAR\r\n", encoding="utf-8", newline="")
    return Path(path)


def exchange_json(path: Path) -> Path:
    doc = {"format": "lunatic-exchange", "version": 1, "source": {"tool": "synthetic", "note": "fictitious data"},
           "records": [
               {"id": "x1", "category": "message", "timestamp": "2026-03-16T10:00:00Z", "direction": "incoming",
                "counterpart": DAN[1], "body": "Message importe depuis un format d'echange", "conversation_id": "x:dan"},
               {"id": "x2", "category": "call", "timestamp": "2026-03-16T10:05:00Z", "direction": "outgoing",
                "counterpart": DAN[1], "duration": 60},
               {"id": "x3", "category": "location", "timestamp": "2026-03-16T10:10:00Z", "latitude": 48.8566,
                "longitude": 2.3522, "location_kind": "estimated"}]}
    Path(path).write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return Path(path)


def exchange_csv(path: Path) -> Path:
    Path(path).write_text("category,timestamp,direction,counterpart,name,body,duration,latitude,longitude,conversation_id\n"
                          f"contact,,,{BOB[1]},Bob Durand,,,,,\n"
                          f"message,2026-03-16 11:00:00,outgoing,{BOB[1]},,Message CSV,,,,csv:bob\n", encoding="utf-8")
    return Path(path)


def google_records(path: Path) -> Path:
    doc = {"locations": [
        {"latitudeE7": 488443400, "longitudeE7": 23738600, "accuracy": 12, "source": "GPS",
         "timestamp": (BASE + timedelta(minutes=1440 + 112)).isoformat().replace("+00:00", "Z")},
        {"latitudeE7": 488530000, "longitudeE7": 23499000, "accuracy": 900, "source": "CELL",
         "timestampMs": str(ms(1440 + 310))}]}
    Path(path).write_text(json.dumps(doc))
    return Path(path)


def gpx(path: Path) -> Path:
    Path(path).write_text('<?xml version="1.0"?><gpx version="1.1" creator="synthetic" xmlns="http://www.topografix.com/GPX/1/1">'
                          '<trk><trkseg><trkpt lat="48.8450" lon="2.3730"><time>2026-03-15T09:50:00Z</time></trkpt>'
                          '<trkpt lat="48.8444" lon="2.3739"><time>2026-03-15T09:56:00Z</time></trkpt></trkseg></trk></gpx>')
    return Path(path)


def logcat(path: Path) -> Path:
    Path(path).write_text("03-15 10:55:01.123  1234  1250 I ActivityManager: Start proc com.whatsapp\n"
                          "03-15 10:55:02.456  1234  1251 W WifiService: Connection lost\n"
                          "03-15 10:56:10.000  2222  2222 E SyntheticApp: Synthetic error for tests\n")
    return Path(path)


def sqlite_with_deleted(path: Path) -> Path:
    """Database where records were deleted without secure_delete -> residual data."""
    p = _db(path, "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);", secure_delete=False)
    con = sqlite3.connect(p)
    con.execute("PRAGMA secure_delete=OFF")
    con.executemany("INSERT INTO notes (body) VALUES (?)",
                    [(f"Note conservee numero {i} " + "x" * 50,) for i in range(40)] +
                    [("SECRET-EFFACE rendez-vous entrepot synthetique",)] +
                    [(f"Note conservee numero {i} " + "x" * 50,) for i in range(40, 80)] +
                    [("padding " * 60,) for _ in range(60)])
    con.commit()
    # bulk delete at the end of the table -> freed pages (free-list)
    con.execute("DELETE FROM notes WHERE body LIKE 'padding%'")
    con.commit()
    # single-row delete inside a used page -> freeblock (no rebalancing)
    con.execute("DELETE FROM notes WHERE body LIKE 'SECRET-EFFACE%'")
    con.commit()
    con.close()
    return p


def raw_image_with_files(path: Path) -> Path:
    import os
    jpg = Path(path).with_suffix(".tmp.jpg")
    jpeg_with_gps(jpg)
    png = Path(path).with_suffix(".tmp.png")
    png_plain(png)
    data = os.urandom(4096).replace(b"\xff\xd8\xff", b"\x00\x00\x00").replace(b"\x89PNG", b"\x00PNG") \
        .replace(b"%PDF-", b"%PDX-")
    blob = data + jpg.read_bytes() + b"\x00" * 1000 + png.read_bytes() + b"\x00" * 512
    Path(path).write_bytes(blob)
    jpg.unlink()
    png.unlink()
    return Path(path)


# ----------------------------------------------------------- hostile inputs
def zip_traversal(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("ok.txt", "fine")
        z.writestr("../../evil.txt", "escape attempt")
    return Path(path)


def zip_bomb(path: Path, size_mb: int = 50) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb.bin", b"\x00" * (size_mb * 1024 * 1024))
    return Path(path)


def tar_with_symlink(path: Path) -> Path:
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("link_to_passwd")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
        payload = b"regular content"
        ri = tarfile.TarInfo("regular.txt")
        ri.size = len(payload)
        tf.addfile(ri, io.BytesIO(payload))
    return Path(path)


def tar_traversal(path: Path) -> Path:
    with tarfile.open(path, "w") as tf:
        payload = b"x"
        ti = tarfile.TarInfo("../outside.txt")
        ti.size = 1
        tf.addfile(ti, io.BytesIO(payload))
    return Path(path)


def xml_billion_laughs(path: Path) -> Path:
    Path(path).write_text('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>'
                          '<smses><sms address="1" date="1" type="1" body="&lol2;"/></smses>')
    return Path(path)


# ------------------------------------------------------------- full dataset
def build_demo_dataset(dest: Path) -> dict[str, Path]:
    """Create a complete, coherent synthetic scenario under ``dest``."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    out: dict[str, Path] = {}
    ext = dest / "android_logical_export"
    (ext / "databases").mkdir(parents=True, exist_ok=True)
    (ext / "DCIM").mkdir(exist_ok=True)
    (ext / "Download").mkdir(exist_ok=True)
    (ext / "adb").mkdir(exist_ok=True)
    android_calllog(ext / "databases" / "calllog.db")
    android_calendar(ext / "databases" / "calendar.db")
    chrome_history(ext / "data" / "data" / "com.android.chrome" / "app_chrome" / "Default" / "History")
    chrome_cookies(ext / "data" / "data" / "com.android.chrome" / "app_chrome" / "Default" / "Cookies")
    chrome_bookmarks(ext / "data" / "data" / "com.android.chrome" / "app_chrome" / "Default" / "Bookmarks")
    whatsapp_android_legacy(ext / "data" / "data" / "com.whatsapp" / "databases" / "msgstore.db")
    (ext / "data" / "data" / "org.thoughtcrime.securesms" / "databases").mkdir(parents=True, exist_ok=True)
    (ext / "data" / "data" / "org.thoughtcrime.securesms" / "databases" / "signal.db").write_bytes(b"\x8a\x13" + bytes(range(256)) * 8)
    jpeg_with_gps(ext / "DCIM" / "IMG_20260315_105500.jpg")
    mp4_with_location(ext / "DCIM" / "VID_20260315_111000.mp4")
    docx(ext / "Download" / "plan.docx")
    pdf(ext / "Download" / "dossier.pdf")
    adb_getprop(ext / "adb" / "getprop.txt")
    adb_packages(ext / "adb" / "packages.txt")
    logcat(ext / "adb" / "logcat.txt")
    google_records(ext / "Takeout_Records.json")
    gpx(ext / "track.gpx")
    sqlite_with_deleted(ext / "databases" / "notes_app.db")
    zpath = dest / "android_logical_export.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(ext.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(ext).as_posix())
    out["android_zip"] = zpath
    out["android_backup"] = android_backup(dest / "android_backup.ab")
    out["ios_backup"] = ios_backup(dest / "ios_backup_00008110")
    out["whatsapp_ios"] = whatsapp_ios(dest / "ChatStorage.sqlite")
    out["sms_xml"] = sms_backup_restore_xml(dest / "sms-20260317.xml")
    out["vcard"] = vcard(dest / "contacts.vcf")
    out["ics"] = icalendar(dest / "agenda.ics")
    out["exchange_json"] = exchange_json(dest / "exchange.json")
    out["exchange_csv"] = exchange_csv(dest / "exchange.csv")
    out["raw_image"] = raw_image_with_files(dest / "usb_stick.img")
    (dest / "README_SYNTHETIC.txt").write_text(
        "All files in this folder are SYNTHETIC test data generated by LUNATIC MOBILE FORENSICS.\n"
        "Names, numbers (+33 6 39 98 xx xx fiction range) and e-mails (example.org) are fictitious.\n")
    return out
