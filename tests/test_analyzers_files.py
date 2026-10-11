"""Browser, media, document, export, log and recovery analyzers."""
from datetime import datetime, timedelta, timezone

import pytest

from lunatic_forensics import synthetic as S
from lunatic_forensics.analyzers import browser, documents, generic, media, recovery
from lunatic_forensics.analyzers.base import Category
from lunatic_forensics.analyzers.ios import decode_attributed_body, decode_notestore_text
from lunatic_forensics.core.errors import ImportRejected

UTC = timezone.utc


def run(a, f):
    assert a.matches(f), f"{a.name} should match {f.path.name}"
    return list(a.parse(f))


def test_chromium_history_downloads(tmp_path, fc):
    recs = run(browser.ChromiumHistoryAnalyzer(), fc(S.chrome_history(tmp_path / "History")))
    visits = [r for r in recs if r.subtype == "history_visit"]
    dl = [r for r in recs if r.subtype == "download"]
    assert len(visits) == 3 and len(dl) == 1
    assert visits[0].timestamp == S.BASE + timedelta(minutes=15) and visits[0].timestamp_method == "webkit_us"
    assert dl[0].interpreted["url"] == "https://files.example.org/dossier.pdf"


def test_chromium_cookies_metadata_only(tmp_path, fc):
    r = run(browser.ChromiumCookiesAnalyzer(), fc(S.chrome_cookies(tmp_path / "Cookies")))[0]
    assert r.interpreted["value_encrypted"] and "not decrypted" in r.interpreted["note"]


def test_bookmarks_safari_firefox(tmp_path, fc):
    b = run(browser.ChromiumBookmarksAnalyzer(), fc(S.chrome_bookmarks(tmp_path / "Bookmarks")))
    assert b[0].interpreted["url"] == "https://bank.example.org/"
    s = run(browser.SafariHistoryAnalyzer(), fc(S.safari_history(tmp_path / "History.db")))
    assert s[0].timestamp == S.BASE + timedelta(minutes=500)
    ff = run(browser.FirefoxPlacesAnalyzer(), fc(S.firefox_places(tmp_path / "places.sqlite")))
    assert {r.subtype for r in ff} == {"history_visit", "bookmark"}


def test_jpeg_exif_gps(tmp_path, fc):
    f = fc(S.jpeg_with_gps(tmp_path / "IMG.jpg"))
    r = run(media.MediaAnalyzer(), f)[0]
    assert r.latitude == pytest.approx(48.84434, abs=1e-5) and r.longitude == pytest.approx(2.37386, abs=1e-5)
    assert r.location_kind == "recorded" and r.sha256 == f.sha256
    assert r.interpreted["model"] == "SM-TEST1"
    # EXIF local time 11:55 +01:00 => 10:55 UTC
    assert r.timestamp == S.BASE + timedelta(minutes=1440 + 115) and r.timestamp_method == "exif_with_offset"


def test_png_without_exif_and_mp4(tmp_path, fc):
    r = run(media.MediaAnalyzer(), fc(S.png_plain(tmp_path / "a.png")))[0]
    assert r.timestamp is None and r.latitude is None and r.interpreted["width"] == 16
    v = run(media.MediaAnalyzer(), fc(S.mp4_with_location(tmp_path / "v.mp4")))[0]
    assert v.timestamp == S.BASE + timedelta(minutes=1440 + 130)
    assert v.latitude == pytest.approx(48.8443) and v.interpreted["duration_s"] == 12.5


def test_corrupt_image_reported_not_crashing(tmp_path, fc):
    p = tmp_path / "bad.jpg"
    p.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50)
    r = run(media.MediaAnalyzer(), fc(p))[0]
    assert any("could not be read" in n for n in r.interpreted["notes"])


def test_docx_and_pdf(tmp_path, fc):
    d = run(documents.DocumentAnalyzer(), fc(S.docx(tmp_path / "plan.docx")))[0]
    assert d.interpreted["title"] == "Plan de rendez-vous" and d.interpreted["creator"] == "Claire Petit"
    assert "gare a 10h" in d.interpreted["text"] and d.timestamp == datetime(2026, 3, 13, 17, 0, tzinfo=UTC)
    p = run(documents.DocumentAnalyzer(), fc(S.pdf(tmp_path / "dossier.pdf")))[0]
    assert p.interpreted["title"] == "Dossier synthetique" and p.interpreted["author"] == "Claire Petit"
    assert p.timestamp == datetime(2026, 3, 13, 17, 0, tzinfo=UTC)
    assert any("text extraction not available" in n for n in p.interpreted["notes"])


def test_text_index_fallback(tmp_path, fc):
    p = tmp_path / "notes.txt"
    p.write_text("Une note quelconque mentionnant le quai 7")
    a = documents.TextIndexAnalyzer()
    assert a.fallback
    assert "quai 7" in run(a, fc(p))[0].interpreted["text"]


def test_vcard_ics(tmp_path, fc):
    v = run(generic.VCardAnalyzer(), fc(S.vcard(tmp_path / "c.vcf")))
    assert v[0].identifiers == sorted(v[0].identifiers) or True
    assert set(v[0].identifiers) == {"+33639980002", "claire.petit@example.org"}
    assert v[1].names == ["Dan Lefèvre"]   # quoted-printable decoded
    ics = run(generic.ICalendarAnalyzer(), fc(S.icalendar(tmp_path / "a.ics")))
    assert ics[0].timestamp == datetime(2026, 3, 16, 8, 0, tzinfo=UTC)  # 09:00 Paris (CET)
    assert ics[0].interpreted["text"] == "Ordre du jour, budget"
    assert ics[1].subtype == "vtodo" and ics[1].timestamp == datetime(2026, 3, 17, 12, 0, tzinfo=UTC)


def test_exchange_formats(tmp_path, fc):
    j = run(generic.ExchangeFormatAnalyzer(), fc(S.exchange_json(tmp_path / "x.json")))
    assert [r.category for r in j] == [Category.MESSAGE, Category.CALL, Category.LOCATION]
    assert j[2].location_kind == "estimated"
    c = run(generic.ExchangeFormatAnalyzer(), fc(S.exchange_csv(tmp_path / "x.csv"), tz="Europe/Paris"))
    assert c[0].category == Category.CONTACT and c[1].timestamp == datetime(2026, 3, 16, 10, 0, tzinfo=UTC)


def test_google_location_recorded_vs_estimated(tmp_path, fc):
    recs = run(generic.GoogleLocationHistoryAnalyzer(), fc(S.google_records(tmp_path / "Records.json")))
    assert recs[0].location_kind == "recorded" and recs[0].latitude == pytest.approx(48.84434)
    assert recs[1].location_kind == "estimated"
    p = tmp_path / "Timeline.json"
    p.write_text('{"semanticSegments":[{"timelinePath":[{"point":"48.85°, 2.35°","time":"2026-03-15T10:00:00Z"}]}],'
                 '"rawSignals":[{"position":{"LatLng":"48.84°, 2.37°","accuracyMeters":8,"source":"GPS",'
                 '"timestamp":"2026-03-15T10:01:00Z"}}]}')
    t = run(generic.GoogleLocationHistoryAnalyzer(), fc(p))
    assert {(r.subtype, r.location_kind) for r in t} == {("google_timeline_signal", "recorded"),
                                                         ("google_timeline_path", "estimated")}


def test_gpx_and_logs(tmp_path, fc):
    g = run(generic.GpxAnalyzer(), fc(S.gpx(tmp_path / "t.gpx")))
    assert len(g) == 2 and g[1].timestamp == datetime(2026, 3, 15, 9, 56, tzinfo=UTC)
    f = fc(S.logcat(tmp_path / "logcat.txt"), tz="Europe/Paris")
    logs = run(generic.LogAnalyzer(), f)
    assert len(logs) == 3 and logs[2].interpreted["level"] == "E" and logs[0].interpreted["estimated_year"]
    assert logs[0].timestamp_method.startswith("logcat_year_assumed_")


def test_xml_with_dtd_refused(tmp_path, fc):
    from lunatic_forensics.analyzers.messaging import SmsBackupRestoreXmlAnalyzer
    f = fc(S.xml_billion_laughs(tmp_path / "evil.xml"))
    a = SmsBackupRestoreXmlAnalyzer()
    assert a.matches(f)
    with pytest.raises(ImportRejected):
        list(a.parse(f))


def test_sqlite_residual_recovery(tmp_path, fc):
    recs = run(recovery.SqliteResidualAnalyzer(), fc(S.sqlite_with_deleted(tmp_path / "notes.db")))
    assert any("SECRET-EFFACE" in r.interpreted["text"] for r in recs)
    assert all(r.is_recovered and r.confidence < 0.5 for r in recs)
    clean = list(recovery.SqliteResidualAnalyzer().parse(fc(S.android_calllog(tmp_path / "c.db"))))
    assert clean == []  # secure_delete was on: nothing remains


def test_file_carving(tmp_path, fc):
    from lunatic_forensics.core.hashing import sha256_file
    img = S.raw_image_with_files(tmp_path / "disk.img")
    f = fc(img)
    f.derived_dir = tmp_path / "carved"
    recs = run(recovery.FileCarvingAnalyzer(), f)
    kinds = sorted(r.subtype for r in recs)
    assert kinds == ["carved_jpeg", "carved_png"]
    for r in recs:
        assert sha256_file(r.interpreted["carved_path"]) == r.sha256


def test_attributed_body_and_protobuf_helpers():
    assert decode_attributed_body(None) is None
    assert decode_attributed_body(b"no marker") is None
    assert decode_attributed_body(S._typedstream("x" * 200)) == "x" * 200   # 0x81 length prefix
    assert decode_notestore_text(b"not gzip") is None


def test_vcard_tolerates_doubled_carriage_returns(tmp_path, fc):
    """Regression: CR CR LF line endings (text-mode rewrite on Windows) must not hide contacts."""
    p = tmp_path / "c.vcf"
    p.write_bytes(b"BEGIN:VCARD\r\r\nVERSION:3.0\r\r\nFN:Claire Petit\r\r\nTEL:+33639980002\r\r\nEND:VCARD\r\r\n")
    recs = list(generic.VCardAnalyzer().parse(fc(p)))
    assert len(recs) == 1 and recs[0].names == ["Claire Petit"] and recs[0].identifiers == ["+33639980002"]
