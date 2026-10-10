"""Android / iOS / messaging analyzers on synthetic databases with exact expectations."""
from datetime import datetime, timedelta, timezone

from lunatic_forensics import synthetic as S
from lunatic_forensics.analyzers import android, ios, messaging
from lunatic_forensics.analyzers.base import Category

UTC = timezone.utc


def at(minutes):
    return S.BASE + timedelta(minutes=minutes)


def run(analyzer, f):
    assert analyzer.matches(f), f"{analyzer.name} should match {f.path.name}"
    return list(analyzer.parse(f))


def test_android_sms_and_mms(tmp_path, fc):
    f = fc(S.android_mmssms(tmp_path / "mmssms.db"))
    recs = run(android.AndroidSmsAnalyzer(), f)
    sms = [r for r in recs if r.subtype == "sms"]
    mms = [r for r in recs if r.subtype == "mms"]
    assert len(sms) == len(S.CONVERSATION) and len(mms) == 1
    first = sms[0]
    assert first.timestamp == at(0) and first.direction == "incoming"
    assert first.identifiers == ["+33639980001"]          # national format normalised
    assert first.raw["address"] == "0639980001"            # original preserved
    assert first.interpreted["body"] == S.CONVERSATION[0][3]
    assert first.source_table == "sms" and first.source_rowid == "1"
    assert sms[1].direction == "outgoing"
    assert mms[0].identifiers == ["+33639980002"] and "photo" in mms[0].interpreted["body"]
    assert mms[0].interpreted["attachments"] == ["image/jpeg"]


def test_android_contacts(tmp_path, fc):
    recs = run(android.AndroidContactsAnalyzer(), fc(S.android_contacts2(tmp_path / "contacts2.db")))
    assert len(recs) == 4
    bob = recs[0]
    assert bob.names == ["Bob Durand"] and "+33639980001" in bob.identifiers
    assert "bob.durand@example.org" in bob.identifiers
    assert bob.interpreted["phones_raw"] == ["0639980001"]
    # second Bob entry (other account) has no e-mail: not identical content, but shares the phone number
    assert recs[0].content_hash() != recs[3].content_hash()
    assert set(recs[0].identifiers) & set(recs[3].identifiers) == {"+33639980001"}


def test_android_calllog(tmp_path, fc):
    recs = run(android.AndroidCallLogAnalyzer(), fc(S.android_calllog(tmp_path / "calllog.db")))
    assert [r.direction for r in recs] == ["incoming", "outgoing", "missed", "outgoing"]
    assert recs[0].interpreted["duration_s"] == 125 and recs[0].timestamp == at(10)


def test_android_calendar(tmp_path, fc):
    recs = run(android.AndroidCalendarAnalyzer(), fc(S.android_calendar(tmp_path / "calendar.db")))
    assert recs[0].interpreted["title"] == "Rendez-vous gare" and recs[0].timestamp == at(1440 + 120)


def test_adb_outputs(tmp_path, fc):
    p = run(android.AdbGetpropAnalyzer(), fc(S.adb_getprop(tmp_path / "getprop.txt")))[0]
    assert p.category == Category.DEVICE and p.interpreted["ro.product.model"] == "SM-TEST1"
    pk = run(android.AdbPackagesAnalyzer(), fc(S.adb_packages(tmp_path / "packages.txt")))
    assert [r.interpreted["package"] for r in pk] == ["com.whatsapp", "com.android.chrome", "org.example.notes"]
    assert pk[1].interpreted["system_app"] is True


def test_adb_content_query(tmp_path, fc):
    p = tmp_path / "content_sms.txt"
    p.write_text(f"Row: 0 _id=1, thread_id=1, address=0639980001, date={S.ms(0)}, type=1, body=Bonjour, ca va, bien ?\n"
                 f"Row: 1 _id=2, thread_id=1, address=+33639980001, date={S.ms(5)}, type=2, body=NULL\n")
    recs = run(android.AdbContentQueryAnalyzer(), fc(p))
    assert recs[0].interpreted["body"] == "Bonjour, ca va, bien ?"
    assert recs[0].identifiers == ["+33639980001"] and recs[0].timestamp == at(0)
    assert recs[1].direction == "outgoing" and recs[1].interpreted["body"] == ""


def test_ios_sms_including_attributed_body(tmp_path, fc):
    recs = run(ios.IosSmsAnalyzer(), fc(S.ios_sms(tmp_path / "sms.db")))
    assert len(recs) == len(S.CONVERSATION)
    assert recs[0].timestamp_method == "mac_absolute_ns"
    assert abs((recs[0].timestamp - at(0)).total_seconds()) < 1
    assert recs[0].subtype == "imessage" and recs[2].subtype == "sms"
    assert recs[1].interpreted["body"] == S.CONVERSATION[1][3]
    assert "heuristic" in recs[1].interpreted["text_source"]
    assert recs[2].interpreted["attachments"][0]["mime"] == "image/jpeg"
    assert recs[6].identifiers == ["dan.lefevre@example.org"]
    assert recs[0].conversation_id == "ios-chat:+33639980001"


def test_ios_addressbook_callhistory_calendar(tmp_path, fc):
    ab = run(ios.IosAddressBookAnalyzer(), fc(S.ios_addressbook(tmp_path / "AddressBook.sqlitedb")))
    assert ab[1].interpreted["phones"] == ["+33639980002"]   # "06 39 98 00 02" normalised
    ch = run(ios.IosCallHistoryAnalyzer(), fc(S.ios_callhistory(tmp_path / "CallHistory.storedata")))
    assert [c.direction for c in ch] == ["incoming", "outgoing", "missed", "outgoing"]
    assert ch[1].subtype == "facetime_audio" and ch[0].timestamp == at(10)
    cal = run(ios.IosCalendarAnalyzer(), fc(S.ios_calendar(tmp_path / "Calendar.sqlitedb")))
    assert cal[0].interpreted["location"] == "Cafe synthetique, Paris"


def test_ios_notes_protobuf_and_locked(tmp_path, fc):
    recs = run(ios.IosNotesAnalyzer(), fc(S.ios_notestore(tmp_path / "NoteStore.sqlite")))
    assert recs[0].interpreted["text"] == "Liste: acheter carte SIM, appeler Bob"
    assert recs[1].interpreted["password_protected"] and recs[1].interpreted["text"] is None


def test_ios_photos(tmp_path, fc):
    recs = run(ios.IosPhotosDbAnalyzer(), fc(S.ios_photos(tmp_path / "Photos.sqlite")))
    assert recs[0].category == Category.LOCATION and recs[0].latitude == 48.84434
    assert recs[0].location_kind == "recorded"
    assert recs[1].category == Category.MEDIA and recs[1].latitude is None  # -180 sentinel = no GPS


def test_whatsapp_android_variants(tmp_path, fc):
    a = messaging.WhatsAppAndroidAnalyzer()
    legacy = run(a, fc(S.whatsapp_android_legacy(tmp_path / "msgstore.db")))
    assert len(legacy) == 4 and legacy[0].identifiers == ["+33639980001"]
    assert legacy[2].interpreted["group"] and legacy[2].identifiers == ["+33639980002"]  # group sender
    assert legacy[3].latitude == 48.8443 and legacy[3].interpreted["media_mime"] == "image/jpeg"
    modern = run(a, fc(S.whatsapp_android_modern(tmp_path / "msgstore2.db")))
    assert modern[0].interpreted["schema_variant"] == "modern" and modern[1].longitude == 2.3499


def test_whatsapp_ios(tmp_path, fc):
    recs = run(messaging.WhatsAppIosAnalyzer(), fc(S.whatsapp_ios(tmp_path / "ChatStorage.sqlite")))
    assert recs[0].direction == "incoming" and recs[1].direction == "outgoing"
    assert recs[0].identifiers == ["+33639980003"] and recs[0].names == ["Dan"]


def test_sms_backup_restore_xml(tmp_path, fc):
    recs = run(messaging.SmsBackupRestoreXmlAnalyzer(), fc(S.sms_backup_restore_xml(tmp_path / "sms.xml")))
    assert len(recs) == 3 and recs[0].names == ["Bob Durand"] and recs[0].timestamp == at(0)


def test_specific_analyzers_do_not_match_unrelated_dbs(tmp_path, fc):
    f = fc(S.chrome_history(tmp_path / "History"))
    for a in android.ANALYZERS + ios.ANALYZERS + messaging.ANALYZERS:
        assert not a.matches(f), a.name


def test_corrupted_sqlite_does_not_crash(tmp_path, fc):
    p = tmp_path / "broken.db"
    p.write_bytes(b"SQLite format 3\x00" + b"\xff" * 300)
    f = fc(p)
    assert f.tables() == set()
    assert not android.AndroidSmsAnalyzer().matches(f)
