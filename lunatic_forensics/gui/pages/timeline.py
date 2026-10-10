from __future__ import annotations

from datetime import datetime, timedelta, timezone

from PySide6.QtCore import QDateTime, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QCheckBox, QDateTimeEdit, QLabel, QSplitter, QVBoxLayout, QWidget

from ..artifact_view import ArtifactDetail
from ..theme import COLORS
from ..widgets import DictTableModel, Page, button, h1, hbox, make_table, muted

CATS = ["message", "call", "media", "location", "browser", "calendar", "note", "document", "log", "app"]


class Histogram(QWidget):
    clicked = Signal(str)

    def __init__(self):
        super().__init__()
        self.data: list[tuple[str, int]] = []
        self.setMinimumHeight(130)
        self.setMouseTracking(True)
        self.hover = -1

    def set_data(self, data):
        self.data = data
        self.update()

    def _bar_rect(self, i, n, mx):
        w = self.width() - 50
        h = self.height() - 34
        bw = max(2.0, w / max(1, n))
        v = self.data[i][1]
        bh = h * v / mx if mx else 0
        return QRectF(40 + i * bw, 10 + h - bh, max(1.0, bw - 2), bh)

    def paintEvent(self, ev):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(COLORS["panel"]))
        if not self.data:
            p.setPen(QColor(COLORS["muted"]))
            p.drawText(self.rect(), Qt.AlignCenter, "No dated events")
            return
        mx = max(v for _, v in self.data)
        n = len(self.data)
        p.setPen(QPen(QColor(COLORS["line"])))
        p.drawLine(40, self.height() - 24, self.width() - 10, self.height() - 24)
        p.setPen(QColor(COLORS["muted"]))
        p.drawText(2, 20, str(mx))
        for i in range(n):
            r = self._bar_rect(i, n, mx)
            p.fillRect(r, QColor(COLORS["silver"] if i == self.hover else COLORS["accent"]))
        p.drawText(40, self.height() - 6, self.data[0][0])
        p.drawText(self.width() - 90, self.height() - 6, self.data[-1][0])
        if 0 <= self.hover < n:
            k, v = self.data[self.hover]
            p.setPen(QColor(COLORS["text"]))
            p.drawText(self.width() // 2 - 80, 20, f"{k}: {v} event(s)")

    def _index_at(self, x):
        n = len(self.data)
        if not n:
            return -1
        w = self.width() - 50
        i = int((x - 40) / max(2.0, w / n))
        return i if 0 <= i < n else -1

    def mouseMoveEvent(self, ev):
        self.hover = self._index_at(ev.position().x())
        self.update()

    def mousePressEvent(self, ev):
        i = self._index_at(ev.position().x())
        if i >= 0:
            self.clicked.emit(self.data[i][0])


class TimelinePage(Page):
    title = "Timeline"

    def __init__(self, main):
        super().__init__(main)
        self.page = 0
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.start = QDateTimeEdit()
        self.end = QDateTimeEdit()
        for w in (self.start, self.end):
            w.setCalendarPopup(True)
            w.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.start.setDateTime(QDateTime.currentDateTime().addYears(-5))
        self.end.setDateTime(QDateTime.currentDateTime().addDays(1))
        self.cbs = {c: QCheckBox(c) for c in CATS}
        for c, cb in self.cbs.items():
            cb.setChecked(c not in ("log", "app"))
        lay.addLayout(hbox(h1("Global timeline"), None, QLabel("From"), self.start, QLabel("to"), self.end,
                           button("Full range", self.full_range), button("Apply", self.refresh, "Primary"), stretch_end=False))
        lay.addLayout(hbox(*self.cbs.values()))
        lay.addWidget(muted("Times are normalised to UTC and displayed in the case timezone. Click a bar to zoom on a day. "
                            "Recovered fragments are excluded (no reliable time)."))
        self.hist = Histogram()
        self.hist.clicked.connect(self._zoom_day)
        lay.addWidget(self.hist)
        self.periods = muted("")
        lay.addWidget(self.periods)
        split = QSplitter(Qt.Horizontal)
        w = QWidget()
        wl = QVBoxLayout(w)
        wl.setContentsMargins(0, 0, 0, 0)
        self.model = DictTableModel([("id", "#"), ("timestamp_utc", "Time"), ("category", "Category"),
                                     ("direction", "Dir."), ("summary", "Event"), ("timestamp_method", "Time decoding"),
                                     ("source_path", "Source")])
        self.table = make_table(self.model, 4)
        self.table.setColumnWidth(1, 170)
        self.table.clicked.connect(lambda i: self.detail.show_artifact(self.model.row(i.row())["id"]))
        wl.addWidget(self.table)
        self.pager = QLabel("")
        wl.addLayout(hbox(button("< Prev", self._prev), self.pager, button("Next >", self._next)))
        split.addWidget(w)
        self.detail = ArtifactDetail(main)
        split.addWidget(self.detail)
        split.setSizes([800, 400])
        lay.addWidget(split, 1)
        self._full = True

    def _cats(self):
        return [c for c, cb in self.cbs.items() if cb.isChecked()]

    def full_range(self):
        self._full = True
        self.refresh()

    def _zoom_day(self, day: str):
        try:
            d = datetime.strptime(day, "%Y-%m-%d")
        except ValueError:
            return
        self._full = False
        self.start.setDateTime(QDateTime(d.year, d.month, d.day, 0, 0))
        self.end.setDateTime(QDateTime(d.year, d.month, d.day, 23, 59))
        self.page = 0
        self.refresh(keep_full=False)

    def refresh(self, keep_full=None):
        if self.case_id is None:
            self.model.set_rows([])
            return
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(self.tz)
        act = self.ctx.correlation.activity(self.session, self.case_id, "day", self._cats())
        self.hist.set_data(act["histogram"])
        per = sorted(act["periods"], key=lambda p: -p["events"])[:3]
        self.periods.setText("Most intense activity periods: " + "; ".join(
            f"{p['start'].astimezone(tz):%Y-%m-%d %H:%M} -> {p['end'].astimezone(tz):%H:%M} ({p['events']} events)" for p in per))
        start = end = None
        if not self._full:
            start = self.start.dateTime().toPython().replace(tzinfo=tz)
            end = self.end.dateTime().toPython().replace(tzinfo=tz)
        rows, total = self.ctx.correlation.timeline(self.session, self.case_id, start, end, self._cats(),
                                                    limit=500, offset=self.page * 500)
        self.model.tz = self.tz
        self.model.set_rows([r.__dict__ for r in rows])
        self.pager.setText(f"{total} events - page {self.page + 1}/{max(1, -(-total // 500))}")

    def _prev(self):
        self.page = max(0, self.page - 1)
        self.refresh()

    def _next(self):
        self.page += 1
        self.refresh()
