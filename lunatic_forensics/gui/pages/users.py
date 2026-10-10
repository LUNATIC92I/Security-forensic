from __future__ import annotations

from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QInputDialog, QLineEdit,
                               QVBoxLayout)

from ... import __app_name__, __version__
from ...core.rbac import ROLE_PERMISSIONS, Perm, Role, has_perm
from ..widgets import DictTableModel, Page, button, confirm, h1, h2, hbox, make_table, muted, selected_rows


class UserDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("New user")
        f = QFormLayout(self)
        self.user, self.name, self.pw = QLineEdit(), QLineEdit(), QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.role = QComboBox()
        self.role.addItems([r.value for r in Role])
        f.addRow("Username", self.user)
        f.addRow("Full name", self.name)
        f.addRow("Role", self.role)
        f.addRow("Initial password", self.pw)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        f.addRow(bb)


def _ask_password(parent, title):
    pw, ok = QInputDialog.getText(parent, title, "Password:", QLineEdit.Password)
    return pw if ok else None


class UsersPage(Page):
    title = "Users & roles"

    def __init__(self, main):
        super().__init__(main)
        admin = has_perm(self.session.role, Perm.MANAGE_USERS)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        btns = [button("Change my password", self.change_own)]
        if admin:
            btns = [button("New user", self.new_user, "Primary"), button("Enable / disable", self.toggle),
                    button("Change role", self.change_role), button("Reset password", self.reset)] + btns + \
                   [button("Encrypted backup...", self.backup)]
        lay.addLayout(hbox(h1("Users & roles"), None, *btns, stretch_end=False))
        lay.addWidget(muted(f"{__app_name__} {__version__}. Roles: administrator (everything), investigator (cases, "
                            "import, acquisition, analysis, reports), analyst (analysis, findings, reports on assigned cases), "
                            "auditor (custody, integrity and audit review - no evidence content)."))
        self.model = DictTableModel([("id", "#"), ("username", "Username"), ("full_name", "Full name"), ("role", "Role"),
                                     ("is_active", "Active"), ("last_login", "Last login"), ("failed_attempts", "Failed"),
                                     ("locked_until", "Locked until"), ("created_at", "Created")])
        self.table = make_table(self.model, 2)
        lay.addWidget(self.table, 1)
        lay.addWidget(h2("Permission matrix"))
        perms = [p for p in Perm]
        self.pm = DictTableModel([("perm", "Permission")] + [(r.value, r.value) for r in Role])
        self.pm.set_rows([{"perm": p.value, **{r.value: ("yes" if p in ROLE_PERMISSIONS[r] else "") for r in Role}}
                          for p in perms])
        lay.addWidget(make_table(self.pm, 0), 1)

    def refresh(self):
        if has_perm(self.session.role, Perm.MANAGE_USERS):
            self.model.set_rows([u.__dict__ for u in self.ctx.auth.list_users(self.session)])
        else:
            self.model.set_rows([{"id": self.session.user_id, "username": self.session.username,
                                  "full_name": self.session.full_name, "role": self.session.role, "is_active": True}])

    def _sel(self):
        rows = selected_rows(self.table)
        return self.model.row(rows[0]) if rows else None

    def new_user(self):
        d = UserDialog(self)
        if d.exec():
            self.guard(self.ctx.auth.create_user, self.session, d.user.text().strip(), d.pw.text(), d.role.currentText(),
                       d.name.text())
            self.refresh()

    def toggle(self):
        u = self._sel()
        if u and confirm(self, "Account", f"{'Disable' if u['is_active'] else 'Enable'} account '{u['username']}'?"):
            self.guard(self.ctx.auth.set_active, self.session, u["id"], not u["is_active"])
            self.refresh()

    def change_role(self):
        u = self._sel()
        if not u:
            return
        role, ok = QInputDialog.getItem(self, "Role", f"Role for {u['username']}:", [r.value for r in Role], 0, False)
        if ok and confirm(self, "Change role", f"Give role '{role}' to {u['username']}?"):
            self.guard(self.ctx.auth.set_role, self.session, u["id"], role)
            self.refresh()

    def reset(self):
        u = self._sel()
        if u:
            pw = _ask_password(self, f"New password for {u['username']}")
            if pw:
                self.guard(self.ctx.auth.reset_password, self.session, u["id"], pw)

    def change_own(self):
        old = _ask_password(self, "Current password")
        if old is None:
            return
        new = _ask_password(self, "New password (12+ chars, upper, lower, digit, symbol)")
        if new:
            if self.guard(self.ctx.auth.change_password, self.session, old, new) is None:
                pass
            self.main.notify("Password change requested.")

    def backup(self):
        pw = _ask_password(self, "Backup passphrase (keep it safe - required for restore)")
        if pw and confirm(self, "Encrypted backup", "Create an encrypted backup of the database, keys and evidence vault?"):
            self.main.run_task("Encrypted backup", self.ctx.backup.create, self.session, pw, with_progress=False,
                               on_done=lambda p: self.main.notify(f"Backup written: {p}"))
