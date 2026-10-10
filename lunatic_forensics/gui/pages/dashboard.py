from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QSplitter, QVBoxLayout, QWidget
from PySide6.QtCore import Qt

from ...core.rbac import Perm, has_perm
from ..theme import COLORS
from ..widgets import DictTableModel, Page, StatCard, button, h1, h2, hbox, make_table, muted


class DashboardPage(Page):
    title = "Dashboard"

    def __init__(self, main):
        super().__init__(main)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.addLayout(hbox(h1("Laboratory dashboard"), None, button("Refresh", self.refresh), stretch_end=False))
        lay.addWidget(muted("Overview of the investigations you are authorised to access."))
        grid = QGridLayout()
        self.c_cases = StatCard("Open investigations")
        self.c_devices = StatCard("Devices")
        self.c_evidence = StatCard("Evidence items")
        self.c_artifacts = StatCard("Artefacts")
        self.c_jobs = StatCard("Analyses running / done")
        self.c_alerts = StatCard("Integrity alerts")
        for i, c in enumerate((self.c_cases, self.c_devices, self.c_evidence, self.c_artifacts, self.c_jobs, self.c_alerts)):
            grid.addWidget(c, i // 3, i % 3)
        lay.addLayout(grid)
        split = QSplitter(Qt.Vertical)
        w1 = QWidget()
        l1 = QVBoxLayout(w1)
        l1.setContentsMargins(0, 0, 0, 0)
        l1.addWidget(h2("Investigations"))
        self.cases_model = DictTableModel([("uid", "Identifier"), ("title", "Title"), ("status", "Status"),
                                           ("owner", "Lead"), ("members", "Authorised investigators"),
                                           ("devices", "Devices"), ("evidence", "Evidence"), ("artifacts", "Artefacts"),
                                           ("jobs", "Analyses running/done"), ("integrity_alerts", "Alerts"),
                                           ("created_at", "Created"), ("updated_at", "Last modified")])
        self.cases_table = make_table(self.cases_model, 1)
        self.cases_table.doubleClicked.connect(self._open_case)
        l1.addWidget(self.cases_table)
        split.addWidget(w1)
        w2 = QWidget()
        l2 = QVBoxLayout(w2)
        l2.setContentsMargins(0, 0, 0, 0)
        l2.addWidget(h2("Evidence integrity alerts"))
        self.alerts_model = DictTableModel([("case", "Case"), ("evidence", "Evidence"), ("name", "Source"),
                                            ("checked_at", "Detected"), ("context", "Context"), ("expected", "Expected SHA-256"),
                                            ("observed", "Observed")])
        l2.addWidget(make_table(self.alerts_model, 2))
        l2.addWidget(h2("Recent analyses"))
        self.jobs_model = DictTableModel([("id", "Job"), ("case_id", "Case #"), ("evidence_id", "Evidence #"),
                                          ("status", "Status"), ("started_by", "By"), ("started_at", "Started"),
                                          ("finished_at", "Finished"), ("artifact_count", "Artefacts")])
        l2.addWidget(make_table(self.jobs_model))
        split.addWidget(w2)
        lay.addWidget(split, 1)

    def refresh(self):
        summ = self.ctx.cases.dashboard(self.session)
        rows = []
        for c in summ:
            r = c.__dict__.copy()
            r["members"] = ", ".join(c.members)
            r["jobs"] = f"{c.jobs_running} / {c.jobs_done}"
            if c.integrity_alerts:
                r["_color"] = COLORS["bad"]
            rows.append(r)
        self.cases_model.set_rows(rows)
        self.c_cases.set(sum(1 for c in summ if c.status in ("open", "in_progress")))
        self.c_devices.set(sum(c.devices for c in summ))
        self.c_evidence.set(sum(c.evidence for c in summ))
        self.c_artifacts.set(f"{sum(c.artifacts for c in summ):,}".replace(",", " "))
        self.c_jobs.set(f"{sum(c.jobs_running for c in summ)} / {sum(c.jobs_done for c in summ)}")
        alerts = self.ctx.cases.integrity_alerts(self.session)
        self.c_alerts.set(len(alerts), COLORS["bad"] if alerts else COLORS["ok"])
        self.alerts_model.set_rows(alerts)
        self.jobs_model.set_rows([j.__dict__ for j in self.ctx.cases.jobs(self.session)[:50]])

    def _open_case(self, idx):
        r = self.cases_model.row(idx.row())
        self.main.reload_cases(r["id"])
        self.main.go("CasesPage")
