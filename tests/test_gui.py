"""GUI smoke tests (offscreen Qt). Skipped when Qt cannot be loaded (e.g. missing libEGL)."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
try:
    from PySide6.QtWidgets import QApplication
except ImportError as exc:  # pragma: no cover
    pytest.skip(f"Qt unavailable: {exc}", allow_module_level=True)

from lunatic_forensics import synthetic as S

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from lunatic_forensics.gui import theme
    app = QApplication.instance() or QApplication([])
    theme.apply(app)
    return app


@pytest.fixture
def loaded_case(ctx, users, case_id, tmp_path):
    inv = users["inv"]
    for p in (S.android_mmssms(tmp_path / "mmssms.db"), S.android_calllog(tmp_path / "calllog.db"),
              S.jpeg_with_gps(tmp_path / "IMG.jpg"), S.google_records(tmp_path / "Records.json"),
              S.android_contacts2(tmp_path / "contacts2.db")):
        ctx.analysis.run(inv, ctx.evidence.import_evidence(inv, case_id, p), correlate=False)
    ctx.correlation.rebuild(inv, case_id)
    return case_id


def test_all_pages_render_for_investigator(qapp, ctx, users, loaded_case):
    from lunatic_forensics.gui.main_window import MainWindow
    win = MainWindow(ctx, users["inv"])
    win.show()
    assert win.case_id == loaded_case
    names = [type(p).__name__ for p in win.pages]
    assert {"DashboardPage", "ArtifactsPage", "TimelinePage", "RelationsPage", "MapPage", "SearchPage",
            "AuditPage", "ReportsPage"} <= set(names)
    for i in range(len(win.pages)):
        win.nav.setCurrentRow(i)
        qapp.processEvents()
    dash = win.page("DashboardPage")
    dash.refresh()
    assert dash.cases_model.rowCount() == 1 and dash.c_artifacts.v.text() != "0"
    arts = win.go("ArtifactsPage")
    arts.tabs.setCurrentIndex(2)  # calls
    calls = arts.browsers[2]
    assert calls.model.rowCount() == 4
    calls._clicked(calls.model.index(0, 0))
    assert calls.detail.current is not None and "Call" in calls.detail.head.text()
    calls.detail._basket()
    assert win.basket
    media = arts.browsers[3]
    media.reload()
    media._clicked(media.model.index(0, 0))
    assert media.detail.preview.pixmap() is not None and not media.detail.preview.pixmap().isNull()
    msgs = arts.browsers[1]
    msgs.reload()
    assert msgs.convs.count() >= 3
    search = win.go("SearchPage")
    search.quick("06 39 98 00 01")
    assert search.model.rowCount() > 0 and search.phone.text()
    tl = win.go("TimelinePage")
    assert tl.model.rowCount() > 0 and tl.hist.data
    rel = win.go("RelationsPage")
    assert rel.edge_model.rowCount() > 0 and rel.view.scene().items()
    mp = win.go("MapPage")
    assert {p["kind"] for p in mp.points} == {"recorded", "estimated"}
    corr = win.go("CorrelationsPage")
    assert corr.model.rowCount() > 0
    rep = win.go("ReportsPage")
    rep.refresh()
    assert "1 artefact" in rep.basket_label.text()
    win.notify("test notification")
    assert win.notifications
    win.tasks.wait_all()
    win.close()


def test_role_based_navigation(qapp, ctx, users, loaded_case):
    from lunatic_forensics.gui.main_window import MainWindow
    win = MainWindow(ctx, users["aud"])
    names = {type(p).__name__ for p in win.pages}
    assert "AuditPage" in names and "ArtifactsPage" not in names and "SearchPage" not in names
    ev = win.page("EvidencePage")
    assert not ev.b_import.isEnabled() and ev.b_verify.isEnabled()
    win.close()


def test_import_wizard_inspection(qapp, ctx, users, case_id, tmp_path):
    from lunatic_forensics.gui.main_window import MainWindow
    from lunatic_forensics.gui.pages.evidence import ImportWizard
    win = MainWindow(ctx, users["inv"])
    page = win.page("EvidencePage")
    wiz = ImportWizard(page)
    wiz.path.setText(str(S.zip_traversal(tmp_path / "bad.zip")))
    wiz.s2.initializePage()
    assert not wiz.s2.isComplete() and "REJECTED" in wiz.s2.pre.toPlainText()
    wiz.path.setText(str(S.vcard(tmp_path / "ok.vcf")))
    wiz.s2.initializePage()
    assert wiz.s2.isComplete()
    params, analyze = wiz.params()
    assert params["path"].endswith("ok.vcf") and analyze
    win.close()


def test_background_task_runs(qapp, ctx, users, case_id, tmp_path):
    from lunatic_forensics.gui.main_window import MainWindow
    win = MainWindow(ctx, users["inv"])
    results = []
    win.run_task("import", ctx.evidence.import_evidence, users["inv"], case_id, S.vcard(tmp_path / "c.vcf"),
                 on_done=results.append)
    import time
    deadline = time.time() + 30
    while (not results or win.tasks.busy()) and time.time() < deadline:
        qapp.processEvents()
        time.sleep(0.01)
    qapp.processEvents()
    assert results and ctx.evidence.list(users["inv"], case_id)
    assert not win.tasks.busy()
    win.close()


def test_force_layout_deterministic():
    from lunatic_forensics.gui.pages.relations import force_layout
    a = force_layout(["a", "b", "c"], [("a", "b", 3), ("b", "c", 1)], 50)
    b = force_layout(["a", "b", "c"], [("a", "b", 3), ("b", "c", 1)], 50)
    assert a == b and len(a) == 3
