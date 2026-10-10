"""Authentication dialogs: first-run administrator, login and session unlock."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit, QMessageBox, QVBoxLayout

from .. import __app_name__, __version__
from ..core.errors import ForensicError
from .widgets import button, hbox, muted


class _Base(QDialog):
    def __init__(self, title: str, subtitle: str):
        super().__init__()
        self.setWindowTitle(f"{__app_name__} - {title}")
        self.setMinimumWidth(420)
        self.lay = QVBoxLayout(self)
        brand = QLabel(__app_name__)
        brand.setObjectName("Brand")
        brand.setAlignment(Qt.AlignCenter)
        sub = QLabel(subtitle)
        sub.setObjectName("BrandSub")
        sub.setAlignment(Qt.AlignCenter)
        self.lay.addWidget(brand)
        self.lay.addWidget(sub)
        self.form = QFormLayout()
        self.lay.addLayout(self.form)
        self.error = QLabel("")
        self.error.setStyleSheet("color: #ff4d4f;")
        self.error.setWordWrap(True)
        self.lay.addWidget(self.error)


class BootstrapDialog(_Base):
    def __init__(self, ctx):
        super().__init__("First run", "CREATE THE ADMINISTRATOR ACCOUNT")
        self.ctx = ctx
        self.user = QLineEdit("admin")
        self.name = QLineEdit("Laboratory administrator")
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.Password)
        for label, w in (("Username", self.user), ("Full name", self.name), ("Password", self.pw), ("Confirm", self.pw2)):
            self.form.addRow(label, w)
        self.lay.addWidget(muted("Password policy: 12+ characters with lowercase, uppercase, digit and symbol. "
                                 "Data stays on this computer; nothing is sent to any server."))
        self.lay.addLayout(hbox(None, button("Create", self.accept_, "Primary"), stretch_end=False))

    def accept_(self):
        if self.pw.text() != self.pw2.text():
            self.error.setText("Passwords do not match.")
            return
        try:
            self.ctx.auth.bootstrap_admin(self.user.text().strip(), self.pw.text(), self.name.text().strip())
        except ForensicError as exc:
            self.error.setText(str(exc))
            return
        self.accept()


class LoginDialog(_Base):
    def __init__(self, ctx):
        super().__init__("Sign in", f"MOBILE FORENSICS PLATFORM  v{__version__}")
        self.ctx = ctx
        self.session = None
        self.user = QLineEdit()
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.returnPressed.connect(self.accept_)
        self.form.addRow("Username", self.user)
        self.form.addRow("Password", self.pw)
        self.lay.addWidget(muted("Use of this software is restricted to authorised investigations. "
                                 "All actions are recorded in a tamper-evident audit log."))
        self.lay.addLayout(hbox(None, button("Sign in", self.accept_, "Primary"), stretch_end=False))

    def accept_(self):
        try:
            self.session = self.ctx.auth.authenticate(self.user.text().strip(), self.pw.text())
        except ForensicError as exc:
            self.error.setText(str(exc))
            self.pw.clear()
            return
        self.accept()


class UnlockDialog(_Base):
    def __init__(self, ctx, session):
        super().__init__("Session locked", "SESSION LOCKED")
        self.ctx, self.session = ctx, session
        self.setWindowFlag(Qt.WindowCloseButtonHint, False)
        self.lay.insertWidget(2, muted(f"The session of '{session.username}' was locked. Enter your password to resume."))
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.returnPressed.connect(self.accept_)
        self.form.addRow("Password", self.pw)
        self.lay.addLayout(hbox(button("Sign out", self.reject), None, button("Unlock", self.accept_, "Primary"),
                                stretch_end=False))

    def accept_(self):
        try:
            self.ctx.auth.unlock(self.session, self.pw.text())
        except ForensicError as exc:
            self.error.setText(str(exc))
            self.pw.clear()
            return
        self.accept()
