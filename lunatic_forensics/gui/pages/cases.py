from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QInputDialog, QLineEdit,
                               QPlainTextEdit, QSplitter, QVBoxLayout, QWidget)

from ...core.rbac import Perm, has_perm
from ...services.case_service import CASE_STATUSES
from ..widgets import DictTableModel, Page, button, confirm, h1, h2, hbox, make_table, muted


class CaseDialog(QDialog):
    def __init__(self, parent, case=None):
        super().__init__(parent)
        self.setWindowTitle("Investigation" if case else "New investigation")
        self.setMinimumWidth(520)
        f = QFormLayout(self)
        self.title = QLineEdit(case.title if case else "")
        self.authority = QLineEdit(case.legal_authority if case else "")
        self.authority.setPlaceholderText("Warrant / requisition / consent reference")
        self.scope = QPlainTextEdit(case.scope if case else "")
        self.scope.setPlaceholderText("Authorised collection and analysis scope")
        self.scope.setMaximumHeight(80)
        self.desc = QPlainTextEdit(case.description if case and case.description else "")
        self.desc.setMaximumHeight(100)
        self.tz = QComboBox()
        self.tz.setEditable(True)
        self.tz.addItems(["UTC", "Europe/Paris", "Europe/London", "Europe/Brussels", "Africa/Casablanca",
                          "Africa/Abidjan", "Africa/Ndjamena", "America/New_York", "America/Montreal", "Asia/Dubai"])
        self.tz.setCurrentText(case.timezone if case else "UTC")
        f.addRow("Title *", self.title)
        f.addRow("Legal authority", self.authority)
        f.addRow("Scope", self.scope)
        f.addRow("Description (encrypted)", self.desc)
        f.addRow("Case timezone", self.tz)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def values(self):
        return dict(title=self.title.text().strip(), description=self.desc.toPlainText(),
                    legal_authority=self.authority.text().strip(), scope=self.scope.toPlainText(),
                    timezone=self.tz.currentText().strip())


class CasesPage(Page):
    title = "Investigations"

    def __init__(self, main):
        super().__init__(main)
        role = self.session.role
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.b_new = button("New investigation", self.new_case, "Primary")
        self.b_edit = button("Edit", self.edit_case)
        self.b_members = button("Add investigator", self.add_member)
        self.b_remove = button("Remove investigator", self.remove_member)
        self.status = QComboBox()
        self.status.addItems(CASE_STATUSES)
        self.b_status = button("Set status", self.set_status)
        for b, perm in ((self.b_new, Perm.CREATE_CASE), (self.b_edit, Perm.EDIT_CASE), (self.b_members, Perm.MANAGE_MEMBERS),
                        (self.b_remove, Perm.MANAGE_MEMBERS), (self.b_status, Perm.EDIT_CASE)):
            b.setEnabled(has_perm(role, perm))
        self.status.setEnabled(has_perm(role, Perm.EDIT_CASE))
        lay.addLayout(hbox(h1("Investigations"), None, self.b_new, self.b_edit, self.b_members, self.b_remove,
                           self.status, self.b_status, stretch_end=False))
        split = QSplitter(Qt.Vertical)
        self.model = DictTableModel([("uid", "Identifier"), ("title", "Title"), ("status", "Status"), ("owner", "Lead"),
                                     ("legal_authority", "Legal authority"), ("timezone", "TZ"),
                                     ("created_at", "Created"), ("updated_at", "Last modified")])
        self.table = make_table(self.model, 1)
        self.table.clicked.connect(self._select)
        split.addWidget(self.table)
        detail = QWidget()
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(0, 0, 0, 0)
        self.info = muted("Select an investigation.")
        dl.addWidget(self.info)
        dl.addWidget(h2("Action history"))
        self.hist = DictTableModel([("timestamp", "Time"), ("username", "User"), ("action", "Action"),
                                    ("object_type", "Object"), ("object_id", "Id"), ("details", "Details")])
        dl.addWidget(make_table(self.hist, 5))
        split.addWidget(detail)
        lay.addWidget(split, 1)

    def refresh(self):
        cases = self.ctx.cases.list_for_user(self.session)
        self.model.tz = self.tz
        rows = []
        for c in cases:
            r = {k: getattr(c, k) for k in ("id", "uid", "title", "status", "legal_authority", "timezone",
                                             "created_at", "updated_at", "scope")}
            r["owner"] = self.ctx.cases.get(self.session, c.id).owner.username
            rows.append(r)
        self.model.set_rows(rows)
        for i, r in enumerate(rows):
            if r["id"] == self.case_id:
                self.table.selectRow(i)
                self._show(r["id"])

    def _select(self, idx):
        cid = self.model.row(idx.row())["id"]
        if cid != self.case_id:
            self.main.reload_cases(cid)
        self._show(cid)

    def _show(self, cid):
        c = self.ctx.cases.get(self.session, cid)
        members = self.ctx.cases.members(self.session, cid)
        self.info.setText(f"<b>{c.uid}</b> - {c.title}<br>Status: {c.status} &middot; Lead: {c.owner.username} &middot; "
                          f"Authorised investigators: {', '.join(members)}<br>Legal authority: {c.legal_authority or '-'}"
                          f"<br>Scope: {c.scope or '-'}<br>Description: {c.description or '-'}")
        if has_perm(self.session.role, Perm.VIEW_AUDIT):
            self.hist.tz = c.timezone
            self.hist.set_rows([e.__dict__ for e in self.ctx.audit.entries(self.session, case_id=cid, limit=300)])
        self.status.setCurrentText(c.status)

    def new_case(self):
        d = CaseDialog(self)
        if d.exec():
            cid = self.guard(self.ctx.cases.create, self.session, **d.values())
            if cid:
                self.main.notify("Investigation created.")
                self.main.reload_cases(cid)
                self.refresh()

    def edit_case(self):
        if not self.needs_case():
            return
        c = self.ctx.cases.get(self.session, self.case_id)
        d = CaseDialog(self, c)
        if d.exec():
            self.guard(self.ctx.cases.update, self.session, self.case_id, **d.values())
            self.main.reload_cases()
            self.refresh()

    def add_member(self):
        if not self.needs_case():
            return
        users = [u.username for u in self.ctx.auth.list_users(self.session) if u.is_active]
        name, ok = QInputDialog.getItem(self, "Authorise investigator", "User:", users, 0, False)
        if ok and name:
            self.guard(self.ctx.cases.add_member, self.session, self.case_id, name)
            self._show(self.case_id)

    def remove_member(self):
        if not self.needs_case():
            return
        members = self.ctx.cases.members(self.session, self.case_id)
        name, ok = QInputDialog.getItem(self, "Revoke access", "User:", members, 0, False)
        if ok and name and confirm(self, "Revoke access", f"Remove {name} from this investigation?"):
            self.guard(self.ctx.cases.remove_member, self.session, self.case_id, name)
            self._show(self.case_id)

    def set_status(self):
        if not self.needs_case():
            return
        st = self.status.currentText()
        if st in ("closed", "archived") and not confirm(self, "Change status",
                                                         f"Set the investigation to '{st}'? No evidence can be added afterwards."):
            return
        self.guard(self.ctx.cases.update, self.session, self.case_id, status=st)
        self.main.reload_cases()
        self.refresh()
