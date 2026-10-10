from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QLabel, QLineEdit, QPlainTextEdit,
                               QSplitter, QTabWidget, QVBoxLayout, QWidget, QWizard, QWizardPage)

from ...core.rbac import Perm, has_perm
from ..theme import COLORS
from ..widgets import DictTableModel, Page, button, confirm, h1, hbox, make_table, muted, selected_rows


class InspectPage(QWizardPage):
    def __init__(self, wiz):
        super().__init__()
        self.wiz = wiz
        self.setTitle("2. Pre-import safety inspection")
        self.setSubTitle("Size, real file type, structure and malicious-content risks are checked before any copy.")
        lay = QVBoxLayout(self)
        self.pre = QPlainTextEdit()
        self.pre.setReadOnly(True)
        lay.addWidget(self.pre)

    def initializePage(self):
        w = self.wiz
        w.report = None
        try:
            w.report = w.p.ctx.evidence.precheck(w.p.session, w.path.text().strip())
        except Exception as exc:  # noqa: BLE001 - shown to the user
            self.pre.setPlainText(f"Inspection failed: {exc}")
            self.completeChanged.emit()
            return
        r = w.report
        lines = [f"Verdict: {'ACCEPTED' if r.accepted else 'REJECTED'}", f"Detected type: {r.detected_type}",
                 f"Size: {r.size} bytes", f"Import plugin: {r.plugin}", ""]
        if r.blocking:
            lines += ["Blocking issues:"] + [f"  - {b}" for b in r.blocking] + [""]
        if r.warnings:
            lines += ["Warnings:"] + [f"  - {x}" for x in r.warnings[:100]] + [""]
        if r.structure:
            import json
            lines += ["Structure:", json.dumps(r.structure, indent=2, default=str)]
        self.pre.setPlainText("\n".join(lines))
        self.completeChanged.emit()

    def isComplete(self):
        return bool(self.wiz.report and self.wiz.report.accepted)


class ConfirmPage(QWizardPage):
    def __init__(self, wiz):
        super().__init__()
        self.wiz = wiz
        self.setTitle("3. Confirmation")
        lay = QVBoxLayout(self)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        lay.addWidget(self.summary)
        lay.addWidget(muted("The source will be hashed (SHA-256), copied into the read-only case vault, verified, then "
                            "extracted to a separate working copy. All steps are written to the audit log."))

    def initializePage(self):
        w = self.wiz
        self.summary.setText(f"<b>Source:</b> {w.path.text()}<br><b>Type:</b> {w.report.detected_type} "
                             f"({w.report.plugin})<br><b>Method:</b> {w.method.currentText()}<br>"
                             f"<b>Warnings:</b> {len(w.report.warnings)}")


class ImportWizard(QWizard):
    """Three steps: source + acquisition metadata -> safety inspection -> confirmation."""

    def __init__(self, page: "EvidencePage"):
        super().__init__(page)
        self.p = page
        self.setWindowTitle("Evidence import assistant")
        self.setMinimumSize(720, 520)
        self.report = None
        # step 1
        s1 = QWizardPage()
        s1.setTitle("1. Source and acquisition context")
        s1.setSubTitle("Select a file (database, archive, backup, media, export) or a folder (iOS backup, exported tree).")
        f = QFormLayout(s1)
        self.path = QLineEdit()
        f.addRow("Source", self.path)
        f.addRow("", hbox(button("Choose file...", self._file), button("Choose folder...", self._dir)))
        self.method = QComboBox()
        self.method.setEditable(True)
        self.method.addItems(["file import", "logical export (vendor tool)", "Android adb backup", "iOS local backup",
                              "ADB logical collection", "cloud export provided by owner", "seized media copy"])
        self.tool = QLineEdit()
        self.tool_v = QLineEdit()
        self.device = QComboBox()
        self.notes = QPlainTextEdit()
        self.notes.setMaximumHeight(70)
        self.analyze = QCheckBox("Run all analyzers after import")
        self.analyze.setChecked(True)
        f.addRow("Acquisition method", self.method)
        f.addRow("Acquisition tool", self.tool)
        f.addRow("Tool version", self.tool_v)
        f.addRow("Device", self.device)
        f.addRow("Notes", self.notes)
        f.addRow("", self.analyze)
        self.addPage(s1)
        self.s2 = InspectPage(self)
        self.addPage(self.s2)
        self.addPage(ConfirmPage(self))
        devs = self.p.ctx.devices.list(self.p.session, self.p.case_id) if self.p.case_id else []
        self.device.addItem("(none / create from backup metadata)", None)
        for d in devs:
            self.device.addItem(f"#{d.id} {d.label} ({d.platform})", d.id)

    def _file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Evidence file")
        if p:
            self.path.setText(p)

    def _dir(self):
        p = QFileDialog.getExistingDirectory(self, "Evidence folder")
        if p:
            self.path.setText(p)

    def params(self):
        return dict(path=self.path.text().strip(), device_id=self.device.currentData(),
                    acquisition_method=self.method.currentText(), tool_name=self.tool.text(),
                    tool_version=self.tool_v.text(), notes=self.notes.toPlainText()), self.analyze.isChecked()


class EvidencePage(Page):
    title = "Evidence"

    def __init__(self, main):
        super().__init__(main)
        role = self.session.role
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.b_import = button("Import evidence...", self.import_wizard, "Primary")
        self.b_import.setEnabled(has_perm(role, Perm.IMPORT_EVIDENCE))
        self.b_analyze = button("Run analysis", self.analyze)
        self.b_analyze.setEnabled(has_perm(role, Perm.RUN_ANALYSIS))
        self.b_verify = button("Verify integrity", self.verify)
        self.b_verify_all = button("Verify all", self.verify_all)
        for b in (self.b_verify, self.b_verify_all):
            b.setEnabled(has_perm(role, Perm.VERIFY_INTEGRITY))
        lay.addLayout(hbox(h1("Evidence"), None, self.b_import, self.b_analyze, self.b_verify, self.b_verify_all,
                           stretch_end=False))
        lay.addWidget(muted("Originals are stored read-only in the case vault; analyses only use working copies."))
        split = QSplitter(Qt.Vertical)
        self.model = DictTableModel([("uid", "ID"), ("original_name", "Source"), ("status", "Status"),
                                     ("container_type", "Container"), ("detected_type", "Type"), ("size", "Bytes"),
                                     ("file_count", "Files"), ("sha256", "SHA-256"), ("acquisition_method", "Method"),
                                     ("imported_at", "Imported")])
        self.table = make_table(self.model, 7)
        self.table.clicked.connect(self._details)
        split.addWidget(self.table)
        tabs = QTabWidget()
        self.files = DictTableModel([("virtual_path", "Logical path"), ("detected_type", "Type"), ("size", "Bytes"),
                                     ("sha256", "SHA-256"), ("mtime", "Modified")])
        tabs.addTab(make_table(self.files, 0), "File inventory")
        self.checks = DictTableModel([("checked_at", "When"), ("context", "Context"), ("checked_by", "By"),
                                      ("ok", "OK"), ("expected", "Expected"), ("observed", "Observed"), ("details", "Details")])
        tabs.addTab(make_table(self.checks, 6), "Integrity checks")
        self.warnings = QPlainTextEdit()
        self.warnings.setReadOnly(True)
        tabs.addTab(self.warnings, "Import warnings & notes")
        split.addWidget(tabs)
        lay.addWidget(split, 1)

    def refresh(self):
        if self.case_id is None:
            self.model.set_rows([])
            return
        self.model.tz = self.files.tz = self.checks.tz = self.tz
        rows = []
        for e in self.ctx.evidence.list(self.session, self.case_id):
            r = dict(e.__dict__)
            if e.status == "integrity_alert":
                r["_color"] = COLORS["bad"]
            rows.append(r)
        self.model.set_rows(rows)

    def _current(self):
        rows = selected_rows(self.table)
        return self.model.row(rows[0]) if rows else None

    def _details(self, idx):
        e = self.model.row(idx.row())
        if has_perm(self.session.role, Perm.VIEW_ARTIFACTS):
            self.files.set_rows([f.__dict__ for f in self.ctx.evidence.files(self.session, e["id"], limit=5000)])
        rows = []
        for c in self.ctx.evidence.checks(self.session, e["id"]):
            r = dict(c.__dict__)
            if not c.ok:
                r["_color"] = COLORS["bad"]
            rows.append(r)
        self.checks.set_rows(rows)
        self.warnings.setPlainText("\n".join(e.get("warnings") or []) + "\n\nNotes:\n" + (e.get("notes") or ""))

    def import_wizard(self):
        if not self.needs_case():
            return
        w = ImportWizard(self)
        if not w.exec():
            return
        params, analyze = w.params()
        if not confirm(self, "Confirm import", f"Import '{Path(params['path']).name}' into the current investigation?"):
            return
        case_id = self.case_id

        def job(progress):
            ev = self.ctx.evidence.import_evidence(self.session, case_id, params.pop("path"), progress=progress, **params)
            if analyze:
                self.ctx.analysis.run(self.session, ev, progress=progress)
            return ev
        self.main.run_task("Evidence import" + (" + analysis" if analyze else ""), job, on_done=lambda _: self.refresh())

    def analyze(self):
        e = self._current()
        if not e:
            self.main.notify("Select an evidence item.", "warn")
            return
        if not confirm(self, "Run analysis", "Run all analyzers on this evidence? Previous artefacts of this evidence "
                                             "will be replaced (the action is audited)."):
            return
        self.main.run_task("Analysis", self.ctx.analysis.run, self.session, e["id"], on_done=lambda _: self.refresh())

    def verify(self):
        e = self._current()
        if not e:
            self.main.notify("Select an evidence item.", "warn")
            return
        c = self.guard(self.ctx.evidence.verify, self.session, e["id"])
        if c:
            self.main.notify(f"{e['uid']}: integrity {'OK' if c.ok else 'ALERT - hash mismatch'}", "info" if c.ok else "error")
            self.refresh()

    def verify_all(self):
        if not self.needs_case():
            return
        self.main.run_task("Integrity verification", self.ctx.evidence.verify_case, self.session, self.case_id,
                           with_progress=False,
                           on_done=lambda checks: (self.main.notify(
                               f"{sum(c.ok for c in checks)}/{len(checks)} evidence items verified OK.",
                               "info" if all(c.ok for c in checks) else "error"), self.refresh()))
