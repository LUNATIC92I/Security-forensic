from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLineEdit, QPlainTextEdit,
                               QSplitter, QVBoxLayout, QWidget)

from ...core.rbac import Perm, has_perm
from ..theme import COLORS
from ..widgets import DictTableModel, Page, button, confirm, h1, h2, hbox, make_table, muted, selected_rows

KIND_COLORS = {"fact": COLORS["ok"], "interpretation": COLORS["accent"], "hypothesis": COLORS["hyp"]}


class FindingDialog(QDialog):
    def __init__(self, parent, basket: set[int]):
        super().__init__(parent)
        self.setWindowTitle("New finding")
        self.setMinimumWidth(560)
        f = QFormLayout(self)
        self.kind = QComboBox()
        self.kind.addItems(["fact", "interpretation", "hypothesis"])
        self.title = QLineEdit()
        self.text = QPlainTextEdit()
        self.ids = QLineEdit(", ".join(str(i) for i in sorted(basket)))
        f.addRow(muted("Fact = directly observed in referenced artefacts (at least one required). Interpretation = "
                       "examiner reading of facts. Hypothesis = possibility to be confirmed."))
        f.addRow("Kind", self.kind)
        f.addRow("Title *", self.title)
        f.addRow("Text", self.text)
        f.addRow("Artefact ids", self.ids)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def values(self):
        ids = [int(x) for x in self.ids.text().replace(";", ",").split(",") if x.strip().isdigit()]
        return self.kind.currentText(), self.title.text(), self.text.toPlainText(), ids


class ReportsPage(Page):
    title = "Findings & reports"

    def __init__(self, main):
        super().__init__(main)
        role = self.session.role
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.b_add = button("New finding...", self.add_finding, "Primary")
        self.b_del = button("Delete finding", self.del_finding, "Danger")
        self.b_add.setEnabled(has_perm(role, Perm.WRITE_FINDINGS))
        self.b_del.setEnabled(has_perm(role, Perm.WRITE_FINDINGS))
        self.b_pdf = button("Generate PDF report", lambda: self.generate("pdf"), "Primary")
        self.b_html = button("Generate HTML report", lambda: self.generate("html"))
        for b in (self.b_pdf, self.b_html):
            b.setEnabled(has_perm(role, Perm.GENERATE_REPORT))
        self.basket_label = muted("")
        lay.addLayout(hbox(h1("Findings & reports"), None, self.b_add, self.b_del, self.b_pdf, self.b_html, stretch_end=False))
        lay.addWidget(muted("Reports contain: cover, case identifier, scope, devices, methods & sources, SHA-256 hashes, results, "
                            "timeline, correlations (facts vs hypotheses), limitations, examiner conclusions, audit-chain status "
                            "and annexes referencing every supporting artefact."))
        lay.addLayout(hbox(self.basket_label, button("Clear basket", self._clear_basket)))
        split = QSplitter(Qt.Vertical)
        w = QWidget()
        wl = QVBoxLayout(w)
        wl.setContentsMargins(0, 0, 0, 0)
        wl.addWidget(h2("Examiner findings"))
        self.fmodel = DictTableModel([("id", "#"), ("kind", "Kind"), ("title", "Title"), ("text", "Text"),
                                      ("artifact_ids", "Supporting artefacts"), ("author", "Author"), ("created_at", "Created")])
        self.ftable = make_table(self.fmodel, 3)
        wl.addWidget(self.ftable)
        split.addWidget(w)
        w2 = QWidget()
        wl2 = QVBoxLayout(w2)
        wl2.setContentsMargins(0, 0, 0, 0)
        wl2.addWidget(h2("Generated reports"))
        self.rmodel = DictTableModel([("generated_at", "Generated"), ("format", "Format"), ("generated_by", "By"),
                                      ("path", "File"), ("sha256", "SHA-256")])
        self.rtable = make_table(self.rmodel, 3)
        self.rtable.doubleClicked.connect(self._open)
        wl2.addWidget(self.rtable)
        wl2.addLayout(hbox(button("Open selected", lambda: self._open(None)), button("Open folder", self._folder)))
        split.addWidget(w2)
        lay.addWidget(split, 1)

    def refresh(self):
        self.basket_label.setText(f"Finding basket: {len(self.main.basket)} artefact(s) "
                                  f"{sorted(self.main.basket)[:15]}")
        if self.case_id is None:
            self.fmodel.set_rows([])
            self.rmodel.set_rows([])
            return
        self.fmodel.tz = self.rmodel.tz = self.tz
        self.fmodel.set_rows([{**f.__dict__, "_color": KIND_COLORS.get(f.kind)}
                              for f in self.ctx.findings.list(self.session, self.case_id)])
        self.rmodel.set_rows([r.__dict__ for r in self.ctx.reports.list(self.session, self.case_id)])

    def _clear_basket(self):
        self.main.basket.clear()
        self.refresh()

    def add_finding(self):
        if not self.needs_case():
            return
        d = FindingDialog(self, self.main.basket)
        if d.exec():
            if self.guard(self.ctx.findings.add, self.session, self.case_id, *d.values()):
                self.main.basket.clear()
                self.refresh()

    def del_finding(self):
        rows = selected_rows(self.ftable)
        if rows and confirm(self, "Delete finding", "Delete the selected finding? (the deletion is audited)"):
            self.guard(self.ctx.findings.delete, self.session, self.fmodel.row(rows[0])["id"])
            self.refresh()

    def generate(self, fmt):
        if not self.needs_case():
            return
        self.main.run_task(f"{fmt.upper()} report", self.ctx.reports.generate, self.session, self.case_id, fmt,
                           with_progress=False, on_done=lambda p: (self.refresh(), self.main.notify(f"Report written: {p}")))

    def _selected_path(self):
        rows = selected_rows(self.rtable)
        return Path(self.rmodel.row(rows[0])["path"]) if rows else None

    def _open(self, _idx):
        p = self._selected_path()
        if p and p.exists():
            self._launch(p)

    def _folder(self):
        if self.case_id is None:
            return
        c = self.ctx.cases.get(self.session, self.case_id)
        p = self.ctx.config.reports_dir / c.uid
        p.mkdir(parents=True, exist_ok=True)
        self._launch(p)

    @staticmethod
    def _launch(p: Path):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))
