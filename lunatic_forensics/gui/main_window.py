"""Main application window: sidebar navigation, case context, notifications, session lock."""
from __future__ import annotations

import logging
from datetime import datetime

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtGui import QAction, QKeySequence, QShortcut
from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QMainWindow, QMenu, QMessageBox, QProgressBar, QStackedWidget, QToolButton,
                               QVBoxLayout, QWidget)

from .. import __app_name__, __version__
from ..core.errors import SessionLocked
from ..core.rbac import Perm, has_perm
from ..core.timeutils import utcnow
from .login import UnlockDialog
from .widgets import QtLogHandler, TaskRunner, show_error

log = logging.getLogger("lunatic.gui")


class ActivityFilter(QObject):
    def __init__(self, win):
        super().__init__()
        self.win = win

    def eventFilter(self, obj, ev):
        if ev.type() in (QEvent.MouseButtonPress, QEvent.KeyPress, QEvent.Wheel):
            self.win.last_input = utcnow()
        return False


class MainWindow(QMainWindow):
    def __init__(self, ctx, session):
        super().__init__()
        self.ctx, self.session = ctx, session
        self.case_id: int | None = None
        self.case_tz = "UTC"
        self.basket: set[int] = set()
        self.last_input = utcnow()
        self.notifications: list[tuple[datetime, str, str]] = []
        self.tasks = TaskRunner(self)
        self.log_handler = QtLogHandler()
        logging.getLogger("lunatic").addHandler(self.log_handler)
        self.setWindowTitle(f"{__app_name__} {__version__} - {session.username} ({session.role})")
        self.resize(1400, 860)
        self.setMinimumSize(980, 620)
        self._build()
        self.reload_cases()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._check_idle)
        self.timer.start(15_000)
        self.activity_filter = ActivityFilter(self)
        from PySide6.QtWidgets import QApplication
        QApplication.instance().installEventFilter(self.activity_filter)
        self.nav.setCurrentRow(0)

    # ------------------------------------------------------------- layout
    def _build(self):
        from .pages import (artifacts, audit, cases, correlations, dashboard, devices, evidence, logs, map_view,
                            relations, reports, search, timeline, users)
        root = QWidget()
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(210)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 8)
        b = QLabel("LUNATIC")
        b.setObjectName("Brand")
        sb = QLabel("MOBILE FORENSICS")
        sb.setObjectName("BrandSub")
        sl.addWidget(b)
        sl.addWidget(sb)
        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        sl.addWidget(self.nav, 1)
        who = QLabel(f"  {self.session.full_name or self.session.username}\n  role: {self.session.role}")
        who.setObjectName("Muted")
        sl.addWidget(who)
        outer.addWidget(side)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)
        top = QFrame()
        top.setObjectName("TopBar")
        tl = QHBoxLayout(top)
        tl.setContentsMargins(12, 6, 12, 6)
        tl.addWidget(QLabel("Case:"))
        self.case_combo = QComboBox()
        self.case_combo.setMinimumWidth(320)
        self.case_combo.currentIndexChanged.connect(self._case_changed)
        tl.addWidget(self.case_combo)
        tl.addStretch(1)
        self.global_search = QLineEdit()
        self.global_search.setPlaceholderText("Global search (phone, e-mail, word, SHA-256)...   Ctrl+K")
        self.global_search.setMinimumWidth(320)
        self.global_search.returnPressed.connect(self._global_search)
        tl.addWidget(self.global_search)
        self.bell = QToolButton()
        self.bell.setText("Notifications (0)")
        self.bell.setPopupMode(QToolButton.InstantPopup)
        self.bell_menu = QMenu(self)
        self.bell.setMenu(self.bell_menu)
        tl.addWidget(self.bell)
        lock = QToolButton()
        lock.setText("Lock")
        lock.setToolTip("Lock the session (Ctrl+L)")
        lock.clicked.connect(self.lock_now)
        tl.addWidget(lock)
        rl.addWidget(top)
        self.stack = QStackedWidget()
        rl.addWidget(self.stack, 1)
        outer.addWidget(right, 1)
        self.setCentralWidget(root)

        self.pages = []
        entries = [("Dashboard", dashboard.DashboardPage, None), ("Investigations", cases.CasesPage, Perm.VIEW_CASE),
                   ("Evidence & import", evidence.EvidencePage, Perm.VIEW_CASE),
                   ("Devices", devices.DevicesPage, Perm.VIEW_CASE),
                   ("Artefacts", artifacts.ArtifactsPage, Perm.VIEW_ARTIFACTS),
                   ("Timeline", timeline.TimelinePage, Perm.VIEW_ARTIFACTS),
                   ("Relations", relations.RelationsPage, Perm.VIEW_ARTIFACTS),
                   ("Map", map_view.MapPage, Perm.VIEW_ARTIFACTS),
                   ("Correlations", correlations.CorrelationsPage, Perm.VIEW_ARTIFACTS),
                   ("Search", search.SearchPage, Perm.VIEW_ARTIFACTS),
                   ("Findings & reports", reports.ReportsPage, Perm.VIEW_ARTIFACTS),
                   ("Audit & custody", audit.AuditPage, Perm.VIEW_AUDIT),
                   ("Technical log", logs.LogsPage, None),
                   ("Users & roles", users.UsersPage, None)]
        for title, cls, perm in entries:
            if perm is not None and not has_perm(self.session.role, perm):
                continue
            page = cls(self)
            self.stack.addWidget(page)
            self.pages.append(page)
            QListWidgetItem(title, self.nav)
        self.nav.currentRowChanged.connect(self._switch)

        self.status = self.statusBar()
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(260)
        self.progress.setVisible(False)
        self.progress_label = QLabel("")
        self.status.addPermanentWidget(self.progress_label)
        self.status.addPermanentWidget(self.progress)
        self.status.showMessage("Local mode - no evidence is transmitted to any remote server.")
        QShortcut(QKeySequence("Ctrl+K"), self, activated=lambda: self.global_search.setFocus())
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self.lock_now)

    def page(self, cls_name: str):
        return next((p for p in self.pages if type(p).__name__ == cls_name), None)

    def go(self, cls_name: str):
        p = self.page(cls_name)
        if p is not None:
            self.nav.setCurrentRow(self.pages.index(p))
        return p

    def _switch(self, row: int):
        if 0 <= row < len(self.pages):
            self.stack.setCurrentIndex(row)
            self.guard(self.pages[row].refresh)

    # -------------------------------------------------------------- cases
    def reload_cases(self, select_id: int | None = None):
        cases = self.guard(self.ctx.cases.list_for_user, self.session) or []
        current = select_id if select_id is not None else self.case_id
        self.case_combo.blockSignals(True)
        self.case_combo.clear()
        self.case_combo.addItem("- no case selected -", None)
        for c in cases:
            self.case_combo.addItem(f"{c.uid}  {c.title}  [{c.status}]", (c.id, c.timezone))
        idx = next((i for i in range(self.case_combo.count()) if (self.case_combo.itemData(i) or (None,))[0] == current), 0)
        if idx == 0 and cases and current is None:
            idx = 1
        self.case_combo.setCurrentIndex(idx)
        self.case_combo.blockSignals(False)
        self._case_changed(idx, refresh=False)

    def _case_changed(self, idx, refresh=True):
        data = self.case_combo.itemData(idx)
        self.case_id, self.case_tz = (data if data else (None, "UTC"))
        if refresh:
            p = self.stack.currentWidget()
            if p is not None:
                self.guard(p.refresh)

    # ------------------------------------------------------- notifications
    def notify(self, msg: str, level: str = "info"):
        self.notifications.insert(0, (utcnow(), level, msg))
        self.notifications = self.notifications[:50]
        self.bell.setText(f"Notifications ({len(self.notifications)})")
        self.bell_menu.clear()
        for ts, lvl, m in self.notifications[:20]:
            act = QAction(f"[{ts.astimezone().strftime('%H:%M:%S')}] {lvl.upper()}: {m}", self)
            self.bell_menu.addAction(act)
        self.bell_menu.addSeparator()
        self.bell_menu.addAction("Clear", self._clear_notifications)
        self.status.showMessage(msg, 8000)
        getattr(log, "warning" if level in ("warn", "error") else "info")(msg)

    def _clear_notifications(self):
        self.notifications.clear()
        self.bell.setText("Notifications (0)")
        self.bell_menu.clear()

    # ---------------------------------------------------------- execution
    def guard(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except SessionLocked:
            self.lock_now(already_locked=True)
        except Exception as exc:  # noqa: BLE001 - user facing
            log.exception("Action failed")
            show_error(self, exc)
        return None

    def run_task(self, label: str, fn, *args, on_done=None, with_progress=True, **kwargs):
        if self.tasks.busy():
            QMessageBox.information(self, "Busy", "Another operation is running. Please wait for it to finish.")
            return
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.progress_label.setText(label)

        def prog(stage, pct):
            self.progress.setValue(pct)
            self.progress_label.setText(f"{label}: {stage[:60]}")

        def done(res):
            self.progress.setVisible(False)
            self.progress_label.setText("")
            self.notify(f"{label} completed.")
            if on_done:
                self.guard(on_done, res)

        def fail(exc):
            self.progress.setVisible(False)
            self.progress_label.setText("")
            self.notify(f"{label} failed: {exc}", "error")
            if isinstance(exc, SessionLocked):
                self.lock_now(already_locked=True)
            else:
                show_error(self, exc)

        self.tasks.start(fn, *args, on_done=done, on_error=fail, on_progress=prog, with_progress=with_progress, **kwargs)

    # ------------------------------------------------------------ locking
    def _check_idle(self):
        if self.session.locked:
            return
        idle = (utcnow() - self.last_input).total_seconds() / 60
        if idle >= self.ctx.config.session_timeout_minutes and not self.tasks.busy():
            self.lock_now()

    def lock_now(self, already_locked: bool = False):
        if getattr(self, "_locking", False):
            return
        self._locking = True
        try:
            if not already_locked and not self.session.locked:
                self.ctx.auth.lock(self.session)
            self.centralWidget().setEnabled(False)
            dlg = UnlockDialog(self.ctx, self.session)
            if dlg.exec():
                self.centralWidget().setEnabled(True)
                self.last_input = utcnow()
            else:
                self.ctx.auth.logout(self.session)
                self.close()
        finally:
            self._locking = False

    def _global_search(self):
        text = self.global_search.text().strip()
        if not text:
            return
        p = self.go("SearchPage")
        if p is not None:
            p.quick(text)

    def closeEvent(self, ev):
        if self.tasks.busy():
            if QMessageBox.question(self, "Operation running", "An operation is still running. Quit anyway?") != QMessageBox.Yes:
                ev.ignore()
                return
            self.tasks.wait_all(5000)
        logging.getLogger("lunatic").removeHandler(self.log_handler)
        from PySide6.QtWidgets import QApplication
        QApplication.instance().removeEventFilter(self.activity_filter)
        if not self.session.revoked:
            self.ctx.auth.logout(self.session)
        super().closeEvent(ev)
