from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QLineEdit, QSplitter, QVBoxLayout, QWidget

from ...core.rbac import Perm, has_perm
from ..theme import COLORS
from ..widgets import DictTableModel, JsonTree, Page, button, h1, h2, hbox, make_table, muted


class AuditPage(Page):
    title = "Audit & custody"

    def __init__(self, main):
        super().__init__(main)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.only_case = QCheckBox("current case only")
        self.only_case.setChecked(True)
        self.prefix = QLineEdit()
        self.prefix.setPlaceholderText("action prefix (evidence., security., case., report. ...)")
        self.prefix.returnPressed.connect(self.refresh)
        lay.addLayout(hbox(h1("Audit trail & chain of custody"), None, button("Verify audit chain", self.verify_chain),
                           button("Verify all evidence", self.verify_evidence), stretch_end=False))
        lay.addWidget(muted("The audit log is append-only and hash-chained: any modification, insertion or deletion breaks "
                            "the chain. Evidence originals are re-hashed (SHA-256) at import, before and after each analysis "
                            "and on demand. A matching hash shows the preserved bytes are unchanged; it does not by itself "
                            "prove authenticity or admissibility."))
        self.chain = muted("")
        lay.addWidget(self.chain)
        lay.addLayout(hbox(self.only_case, self.prefix, button("Filter", self.refresh)))
        split = QSplitter(Qt.Vertical)
        top = QSplitter(Qt.Horizontal)
        self.model = DictTableModel([("id", "#"), ("timestamp", "Time"), ("username", "User"), ("action", "Action"),
                                     ("case_id", "Case"), ("object_type", "Object"), ("object_id", "Id"),
                                     ("entry_hash", "Entry hash")])
        self.table = make_table(self.model, 3)
        self.table.clicked.connect(lambda i: self.tree.show_obj(self.model.row(i.row())["details"] or {}))
        top.addWidget(self.table)
        self.tree = JsonTree()
        top.addWidget(self.tree)
        top.setSizes([900, 350])
        split.addWidget(top)
        w = QWidget()
        wl = QVBoxLayout(w)
        wl.setContentsMargins(0, 0, 0, 0)
        wl.addWidget(h2("Evidence custody status"))
        self.ev_model = DictTableModel([("uid", "Evidence"), ("original_name", "Source"), ("sha256", "Reference SHA-256"),
                                        ("status", "Status"), ("imported_at", "Imported"), ("checks", "Checks"),
                                        ("last", "Last verification")])
        wl.addWidget(make_table(self.ev_model, 2))
        split.addWidget(w)
        lay.addWidget(split, 1)

    def refresh(self):
        cid = self.case_id if self.only_case.isChecked() else None
        self.model.tz = self.ev_model.tz = self.tz
        rows = []
        for e in self.ctx.audit.entries(self.session, case_id=cid, action_prefix=self.prefix.text().strip() or None,
                                        limit=2000):
            r = dict(e.__dict__)
            if e.action.startswith("security.") or "violation" in e.action:
                r["_color"] = COLORS["warn"] if "violation" not in e.action else COLORS["bad"]
            rows.append(r)
        self.model.set_rows(rows)
        evs = []
        if self.case_id is not None:
            for e in self.ctx.evidence.list(self.session, self.case_id):
                checks = self.ctx.evidence.checks(self.session, e.id)
                last = checks[-1] if checks else None
                evs.append({**e.__dict__, "checks": len(checks),
                            "last": f"{'OK' if last and last.ok else 'ALERT'} ({last.context})" if last else "-",
                            "_color": COLORS["bad"] if any(not c.ok for c in checks) else None})
        self.ev_model.set_rows(evs)

    def verify_chain(self):
        ok, broken, n = self.ctx.audit.verify_chain()
        self.chain.setText(f"<b style='color:{COLORS['ok'] if ok else COLORS['bad']}'>Audit chain "
                           f"{'INTACT' if ok else f'BROKEN at entry #{broken}'}</b> - {n} entries - head "
                           f"<code>{self.ctx.audit.head_hash()}</code>")
        self.main.notify(f"Audit chain {'intact' if ok else 'BROKEN'} ({n} entries).", "info" if ok else "error")

    def verify_evidence(self):
        if self.needs_case() and has_perm(self.session.role, Perm.VERIFY_INTEGRITY):
            self.main.run_task("Integrity verification", self.ctx.evidence.verify_case, self.session, self.case_id,
                               with_progress=False, on_done=lambda _: self.refresh())
