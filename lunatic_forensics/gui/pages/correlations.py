from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QSplitter, QVBoxLayout, QWidget

from ...core.rbac import Perm, has_perm
from ..artifact_view import ArtifactDetail
from ..theme import COLORS
from ..widgets import DictTableModel, Page, button, h1, hbox, make_table, muted

KIND_COLORS = {"observed_fact": COLORS["ok"], "hypothesis": COLORS["hyp"], "anomaly": COLORS["bad"]}


class CorrelationsPage(Page):
    title = "Correlations"

    def __init__(self, main):
        super().__init__(main)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.kind = QComboBox()
        self.kind.addItems(["all", "observed_fact", "hypothesis", "anomaly"])
        self.kind.currentIndexChanged.connect(lambda _: self.refresh())
        self.b_rebuild = button("Recompute", self.rebuild)
        self.b_rebuild.setEnabled(has_perm(self.session.role, Perm.RUN_ANALYSIS))
        lay.addLayout(hbox(h1("Correlations"), None, self.kind, self.b_rebuild, stretch_end=False))
        lay.addWidget(muted("Green = observed facts (mechanical equality in the data). Amber = hypotheses: analytical leads "
                            "requiring examiner validation. Red = temporal inconsistencies. Every line lists the artefacts "
                            "that justify it."))
        split = QSplitter(Qt.Vertical)
        self.model = DictTableModel([("kind", "Kind"), ("rule", "Rule"), ("description", "Description"), ("n", "Artefacts")])
        self.table = make_table(self.model, 2)
        self.table.clicked.connect(self._select)
        split.addWidget(self.table)
        bottom = QSplitter(Qt.Horizontal)
        self.refs = DictTableModel([("id", "#"), ("category", "Category"), ("timestamp_utc", "Time"), ("summary", "Summary")])
        self.refs_table = make_table(self.refs, 3)
        self.refs_table.clicked.connect(lambda i: self.detail.show_artifact(self.refs.row(i.row())["id"]))
        bottom.addWidget(self.refs_table)
        self.detail = ArtifactDetail(main)
        bottom.addWidget(self.detail)
        split.addWidget(bottom)
        lay.addWidget(split, 1)

    def refresh(self):
        if self.case_id is None:
            self.model.set_rows([])
            return
        kind = None if self.kind.currentText() == "all" else self.kind.currentText()
        rows = []
        for c in self.ctx.correlation.correlations(self.session, self.case_id, kind):
            rows.append({"kind": c.kind, "rule": c.rule, "description": c.description, "n": len(c.artifact_ids),
                         "ids": c.artifact_ids, "_color": KIND_COLORS.get(c.kind)})
        self.model.set_rows(rows)

    def _select(self, idx):
        ids = self.model.row(idx.row())["ids"][:300]
        arts = [self.ctx.analysis.artifact(self.session, i) for i in ids[:100]]
        self.refs.tz = self.tz
        self.refs.set_rows([a.__dict__ for a in arts])

    def rebuild(self):
        if self.needs_case():
            self.main.run_task("Correlation", self.ctx.correlation.rebuild, self.session, self.case_id,
                               with_progress=False, on_done=lambda n: self.refresh())
