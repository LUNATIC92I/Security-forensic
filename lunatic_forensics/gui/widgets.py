"""Reusable GUI building blocks."""
from __future__ import annotations

import json
import logging
import traceback

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton, QSizePolicy,
                               QTableView, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core.errors import ForensicError, ImportRejected, SessionLocked
from ..core.timeutils import to_display

log = logging.getLogger("lunatic.gui")


def h1(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName("H1")
    return lab


def h2(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName("H2")
    return lab


def muted(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName("Muted")
    lab.setWordWrap(True)
    return lab


def button(text: str, slot=None, kind: str | None = None, tip: str | None = None) -> QPushButton:
    b = QPushButton(text)
    if kind:
        b.setObjectName(kind)
    if slot:
        b.clicked.connect(slot)
    if tip:
        b.setToolTip(tip)
    return b


def hbox(*widgets, stretch_end=True) -> QHBoxLayout:
    lay = QHBoxLayout()
    for w in widgets:
        if isinstance(w, int):
            lay.addSpacing(w)
        elif w is None:
            lay.addStretch(1)
        else:
            lay.addWidget(w)
    if stretch_end:
        lay.addStretch(1)
    return lay


class StatCard(QFrame):
    def __init__(self, title: str, value="0", color: str | None = None):
        super().__init__()
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        self.t = QLabel(title)
        self.t.setObjectName("CardTitle")
        self.v = QLabel(str(value))
        self.v.setObjectName("CardValue")
        if color:
            self.v.setStyleSheet(f"color: {color};")
        lay.addWidget(self.t)
        lay.addWidget(self.v)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set(self, value, color: str | None = None):
        self.v.setText(str(value))
        if color:
            self.v.setStyleSheet(f"color: {color};")


class DictTableModel(QAbstractTableModel):
    """Table model over a list of dicts; columns = [(key, header), ...]."""

    def __init__(self, columns: list[tuple[str, str]], tz: str = "UTC"):
        super().__init__()
        self.columns = columns
        self.rows: list[dict] = []
        self.tz = tz

    def set_rows(self, rows: list[dict]):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.columns)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        key = self.columns[index.column()][0]
        v = row.get(key)
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            if hasattr(v, "isoformat"):
                return to_display(v, self.tz)
            if isinstance(v, bool):
                return "yes" if v else "no"
            if isinstance(v, (list, dict)):
                return json.dumps(v, ensure_ascii=False, default=str)[:300]
            return "" if v is None else str(v)
        if role == Qt.ForegroundRole and "_color" in row:
            from PySide6.QtGui import QColor
            return QColor(row["_color"])
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.columns[section][1]
        return None

    def row(self, i: int) -> dict:
        return self.rows[i]


def make_table(model, stretch_col: int | None = None) -> QTableView:
    t = QTableView()
    t.setModel(model)
    t.setSelectionBehavior(QTableView.SelectRows)
    t.setSelectionMode(QTableView.ExtendedSelection)
    t.setAlternatingRowColors(True)
    t.setSortingEnabled(False)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(24)
    t.setWordWrap(False)
    hh = t.horizontalHeader()
    hh.setSectionResizeMode(QHeaderView.Interactive)
    hh.setStretchLastSection(True)
    hh.setMaximumSectionSize(460)
    hh.setMinimumSectionSize(40)
    model.modelReset.connect(lambda: (t.resizeColumnsToContents(), hh.setStretchLastSection(True)))
    return t


def selected_rows(table: QTableView) -> list[int]:
    return sorted({i.row() for i in table.selectionModel().selectedRows()}) if table.selectionModel() else []


class JsonTree(QTreeWidget):
    def __init__(self):
        super().__init__()
        self.setHeaderLabels(["Field", "Value"])
        self.setColumnWidth(0, 200)
        self.setAlternatingRowColors(True)

    def show_obj(self, obj, title: str | None = None):
        self.clear()
        root = self.invisibleRootItem() if title is None else QTreeWidgetItem(self, [title, ""])
        self._add(root, obj)
        self.expandToDepth(1)

    def _add(self, parent, obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                it = QTreeWidgetItem(parent, [str(k), "" if isinstance(v, (dict, list)) else self._fmt(v)])
                self._add(it, v)
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:500]):
                it = QTreeWidgetItem(parent, [f"[{i}]", "" if isinstance(v, (dict, list)) else self._fmt(v)])
                self._add(it, v)

    @staticmethod
    def _fmt(v):
        s = "" if v is None else str(v)
        return s if len(s) < 2000 else s[:2000] + " ..."


class Worker(QObject):
    progress = Signal(str, int)
    done = Signal(object)
    failed = Signal(object)

    def __init__(self, fn, with_progress: bool, args, kwargs):
        super().__init__()
        self.fn, self.with_progress, self.args, self.kwargs = fn, with_progress, args, kwargs

    @Slot()
    def run(self):
        try:
            kw = dict(self.kwargs)
            if self.with_progress:
                kw["progress"] = lambda stage, pct: self.progress.emit(stage, int(pct))
            self.done.emit(self.fn(*self.args, **kw))
        except Exception as exc:  # noqa: BLE001 - reported to the user
            log.error("Background task failed: %s\n%s", type(exc).__name__, traceback.format_exc())
            self.failed.emit(exc)


class _Relay(QObject):
    """Lives in the GUI thread: worker signals reach it through queued connections,
    so user callbacks always run in the GUI thread (never touch widgets from a worker)."""

    def __init__(self, parent, on_done, on_error, on_progress):
        super().__init__(parent)
        self.on_done, self.on_error, self.on_progress = on_done, on_error, on_progress

    @Slot(object)
    def done(self, res):
        if self.on_done:
            self.on_done(res)

    @Slot(object)
    def failed(self, exc):
        if self.on_error:
            self.on_error(exc)

    @Slot(str, int)
    def progress(self, stage, pct):
        if self.on_progress:
            self.on_progress(stage, pct)


class TaskRunner(QObject):
    """Runs callables in a QThread and keeps references until completion."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._threads: list[tuple[QThread, Worker, _Relay]] = []

    def start(self, fn, *args, on_done=None, on_error=None, on_progress=None, with_progress=False, **kwargs):
        th = QThread()
        w = Worker(fn, with_progress, args, kwargs)
        relay = _Relay(self, on_done, on_error, on_progress)
        w.moveToThread(th)
        th.started.connect(w.run)
        w.progress.connect(relay.progress, Qt.QueuedConnection)
        w.done.connect(relay.done, Qt.QueuedConnection)
        w.failed.connect(relay.failed, Qt.QueuedConnection)
        w.done.connect(th.quit)
        w.failed.connect(th.quit)
        entry = (th, w, relay)
        th.finished.connect(lambda: self._finished(entry))
        self._threads.append(entry)
        th.start()
        return th

    def _finished(self, entry):
        if entry in self._threads:
            self._threads.remove(entry)
            entry[2].deleteLater()

    def busy(self) -> bool:
        return any(th.isRunning() for th, _w, _r in self._threads)

    def wait_all(self, ms: int = 30000):
        for th, _w, _r in list(self._threads):
            th.wait(ms)


def error_message(exc: Exception) -> str:
    if isinstance(exc, ImportRejected):
        return str(exc) + ("\n\n" + "\n".join(f"- {r}" for r in exc.risks[:20]) if exc.risks else "")
    if isinstance(exc, ForensicError):
        return str(exc)
    return f"Unexpected error ({type(exc).__name__}). Technical details were written to the technical log."


def show_error(parent, exc: Exception, title="Operation failed"):
    if isinstance(exc, SessionLocked):
        title = "Session locked"
    QMessageBox.warning(parent, title, error_message(exc))


def confirm(parent, title: str, text: str) -> bool:
    return QMessageBox.question(parent, title, text, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes


class LogBridge(QObject):
    record = Signal(str, str)


class QtLogHandler(logging.Handler):
    """Forwards log records to the GUI thread through a Qt signal."""

    def __init__(self):
        super().__init__()
        self.bridge = LogBridge()
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))

    def emit(self, rec):
        try:
            self.bridge.record.emit(rec.levelname, self.format(rec))
        except RuntimeError:  # bridge deleted during shutdown
            pass


class Page(QWidget):
    title = ""

    def __init__(self, main):
        super().__init__()
        self.setObjectName("Page")
        self.main = main
        self.ctx = main.ctx

    @property
    def session(self):
        return self.main.session

    @property
    def case_id(self):
        return self.main.case_id

    @property
    def tz(self):
        return self.main.case_tz

    def guard(self, fn, *args, **kwargs):
        return self.main.guard(fn, *args, **kwargs)

    def refresh(self):  # pragma: no cover - overridden
        pass

    def needs_case(self) -> bool:
        if self.case_id is None:
            self.main.notify("Select or create a case first.", "warn")
            return False
        return True
