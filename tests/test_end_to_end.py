"""Non-regression test over the complete synthetic scenario.

Expected counts are a snapshot of validated parser output; any change must be
reviewed (a parser regression or an intended improvement).
"""
from lunatic_forensics.synthetic import build_demo_dataset

EXPECTED_COUNTS = {
    "android_zip": {"media.metadata": 2, "documents.metadata": 2, "export.google_location_history": 2,
                    "logs.system": 3, "android.adb_packages": 3, "android.adb_getprop": 1,
                    "browser.chromium_bookmarks": 1, "browser.chromium_cookies": 1, "browser.chromium_history": 4,
                    "messaging.whatsapp_android": 4, "android.calendar": 2, "android.calllog": 4, "export.gpx": 2,
                    "apps.inventory": 3},
    "android_backup": {"android.sms": 8, "android.contacts": 4, "apps.inventory": 2},
    "ios_backup": {"ios.sms": 7, "ios.addressbook": 3, "ios.callhistory": 4, "ios.calendar": 1, "ios.notes": 2,
                   "ios.photos_db": 2, "apps.inventory": 1},
    "whatsapp_ios": {"messaging.whatsapp_ios": 2},
    "sms_xml": {"export.sms_backup_restore_xml": 3},
    "vcard": {"export.vcard": 2},
    "ics": {"export.icalendar": 2},
    "exchange_json": {"export.lunatic_exchange": 3},
    "exchange_csv": {"export.lunatic_exchange": 2},
    "raw_image": {"recovery.file_carving": 2},
}


def test_full_scenario(ctx, users, case_id, tmp_path):
    inv = users["inv"]
    ds = build_demo_dataset(tmp_path / "ds")
    for key, path in ds.items():
        ev = ctx.evidence.import_evidence(inv, case_id, path)
        job = ctx.analysis.job(inv, ctx.analysis.run(inv, ev, correlate=False))
        assert job.status == "completed", (key, job.errors)
        got = {k: v for k, v in job.analyzers.items() if not k.startswith("_") and not k.startswith("recovery.sqlite")
               and k != "documents.text_index"}
        assert got == EXPECTED_COUNTS[key], key
    n = ctx.correlation.rebuild(inv, case_id)
    assert n > 10
    apps = [a for a in ctx.search.search(inv, case_id, __import__("lunatic_forensics.services.search_service",
            fromlist=["SearchQuery"]).SearchQuery(categories=["app"], page_size=100)).hits]
    signal = [h for h in apps if "securesms" in h.summary]
    assert signal  # encrypted Signal store inventoried, never parsed
    checks = ctx.evidence.verify_case(users["aud"], case_id)
    assert checks and all(c.ok for c in checks)
    assert ctx.audit.verify_chain()[0]
    pdf = ctx.reports.generate(inv, case_id, "pdf")
    assert pdf.stat().st_size > 20000
