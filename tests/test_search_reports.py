import pytest

from lunatic_forensics import synthetic as S
from lunatic_forensics.core.errors import PermissionDenied, ValidationError
from lunatic_forensics.services.search_service import SearchQuery


@pytest.fixture
def loaded(ctx, users, case_id, tmp_path):
    inv = users["inv"]
    for p in (S.android_mmssms(tmp_path / "mmssms.db"), S.android_contacts2(tmp_path / "contacts2.db"),
              S.android_calllog(tmp_path / "calllog.db"), S.jpeg_with_gps(tmp_path / "IMG.jpg"),
              S.ios_sms(tmp_path / "sms.db")):
        ctx.analysis.run(inv, ctx.evidence.import_evidence(inv, case_id, p), correlate=False)
    ctx.correlation.rebuild(inv, case_id)
    return case_id


def s(ctx, users, cid, **kw):
    return ctx.search.search(users["ana"], cid, SearchQuery(**kw))


def test_phone_search_any_format(ctx, users, loaded):
    a = s(ctx, users, loaded, phone="06 39 98 00 01")
    b = s(ctx, users, loaded, phone="+33639980001")
    assert a.total == b.total > 5
    assert {h.category for h in a.hits} >= {"message", "call", "contact"}
    h = a.hits[0]
    assert h.evidence_uid.startswith("EV-") and h.source_table and h.source_rowid and h.parser


def test_email_text_deep_dates_category(ctx, users, loaded):
    assert s(ctx, users, loaded, email="DAN.LEFEVRE@example.org").total >= 2
    shallow = s(ctx, users, loaded, text="10h devant la gare")
    deep = s(ctx, users, loaded, text="10h devant la gare", deep=True)
    assert deep.total >= shallow.total >= 1
    from datetime import datetime, timezone
    r = s(ctx, users, loaded, start=datetime(2026, 3, 15, tzinfo=timezone.utc), end=datetime(2026, 3, 15, 23, 59, tzinfo=timezone.utc),
          categories=["message"])
    assert r.total > 0 and all(h.timestamp.day == 15 for h in r.hits)


def test_hash_and_geo_search(ctx, users, loaded, tmp_path):
    from lunatic_forensics.core.hashing import sha256_file
    sha = sha256_file(tmp_path / "IMG.jpg")
    r = s(ctx, users, loaded, sha256=sha.upper())
    assert r.total == 1 and r.hits[0].category == "media" and r.file_hits[0]["sha256"] == sha
    g = s(ctx, users, loaded, min_lat=48.8, max_lat=48.9, min_lon=2.3, max_lon=2.4)
    assert g.total == 1
    assert s(ctx, users, loaded, min_lat=40, max_lat=41, min_lon=2.3, max_lon=2.4).total == 0


def test_pagination(ctx, users, loaded):
    p1 = s(ctx, users, loaded, page_size=5, page=1)
    p2 = s(ctx, users, loaded, page_size=5, page=2)
    assert p1.total == p2.total and p1.pages == -(-p1.total // 5)
    assert not {h.artifact_id for h in p1.hits} & {h.artifact_id for h in p2.hits}


def test_injection_and_wildcards_are_inert(ctx, users, loaded):
    assert s(ctx, users, loaded, text="%").total == 0
    assert s(ctx, users, loaded, text="_").total == 0
    assert s(ctx, users, loaded, text="' OR 1=1 --").total == 0
    assert s(ctx, users, loaded, name="x'; DROP TABLE artifacts; --").total == 0
    assert s(ctx, users, loaded).total > 0  # table still there


def test_validation_and_permissions(ctx, users, loaded):
    with pytest.raises(Exception):
        SearchQuery(sha256="1234")
    with pytest.raises(Exception):
        SearchQuery(page_size=100000)
    with pytest.raises(ValidationError):
        s(ctx, users, loaded, phone="abc")
    with pytest.raises(PermissionDenied):
        ctx.search.search(users["aud"], loaded, SearchQuery())


def test_correlations_and_timeline(ctx, users, loaded):
    corr = ctx.correlation.correlations(users["ana"], loaded)
    rules = {c.rule for c in corr}
    assert {"identifier_matches_contact", "call_message_proximity", "contact_shared_identifier"} <= rules
    assert all(c.artifact_ids for c in corr)
    rows, total = ctx.correlation.timeline(users["ana"], loaded, categories=["message", "call"])
    assert total == len(rows) and all(rows[i].timestamp_utc <= rows[i + 1].timestamp_utc for i in range(len(rows) - 1))
    act = ctx.correlation.activity(users["ana"], loaded)
    assert act["timezone"] == "Europe/Paris" and act["histogram"] and act["periods"]
    g = ctx.correlation.graph(users["ana"], loaded)
    assert any(n["id"] == "+33639980001" for n in g["nodes"])


def test_findings_rules(ctx, users, loaded):
    hit = s(ctx, users, loaded, phone="+33639980001").hits[0]
    with pytest.raises(ValidationError):
        ctx.findings.add(users["ana"], loaded, "fact", "No refs", "x", [])
    with pytest.raises(ValidationError):
        ctx.findings.add(users["ana"], loaded, "opinion", "Bad kind", "x", [hit.artifact_id])
    with pytest.raises(ValidationError):
        ctx.findings.add(users["ana"], loaded, "fact", "Foreign", "x", [999999])
    fid = ctx.findings.add(users["ana"], loaded, "fact", "Contact with Bob", "Messages exchanged.", [hit.artifact_id])
    ctx.findings.add(users["ana"], loaded, "hypothesis", "Meeting planned", "Possible meeting at station.", [])
    assert [f.id for f in ctx.findings.list(users["inv"], loaded)][0] == fid
    with pytest.raises(PermissionDenied):
        ctx.findings.add(users["aud"], loaded, "hypothesis", "x", "", [])


def test_reports_html_pdf(ctx, users, loaded, tmp_path):
    from lunatic_forensics.core.hashing import sha256_file
    hit = s(ctx, users, loaded, phone="+33639980001").hits[0]
    ctx.findings.add(users["ana"], loaded, "fact", "Contact <script>alert(1)</script>", "Body & <b>tags</b>", [hit.artifact_id])
    html = ctx.reports.generate(users["ana"], loaded, "html")
    content = html.read_text()
    assert "<script>alert(1)</script>" not in content and "&lt;script&gt;" in content
    for section in ("Scope of the investigation", "Devices", "Methods, sources", "Analysis results", "Timeline",
                    "Correlations", "Examiner observations", "Technical limitations", "Audit trail", "Annex A", "Annex B"):
        assert section in content
    ev = ctx.evidence.list(users["inv"], loaded)[0]
    assert ev.sha256 in content
    pdf = ctx.reports.generate(users["ana"], loaded, "pdf", output=tmp_path / "r.pdf")
    assert pdf.read_bytes()[:5] == b"%PDF-" and pdf.stat().st_size > 5000
    reps = ctx.reports.list(users["inv"], loaded)
    assert {r.format for r in reps} == {"html", "pdf"} and reps[0].sha256 == sha256_file(reps[0].path)
    with pytest.raises(ValidationError):
        ctx.reports.generate(users["ana"], loaded, "docx")
    with pytest.raises(PermissionDenied):
        ctx.reports.generate(users["aud"], loaded, "html")
