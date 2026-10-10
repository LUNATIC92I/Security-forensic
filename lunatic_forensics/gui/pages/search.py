from __future__ import annotations

from PySide6.QtCore import QDateTime, Qt
from PySide6.QtWidgets import (QCheckBox, QDateTimeEdit, QDoubleSpinBox, QFormLayout, QGridLayout, QGroupBox, QLabel,
                               QLineEdit, QSplitter, QTabWidget, QVBoxLayout, QWidget)

from ...services.search_service import SearchQuery
from ..artifact_view import COLUMNS, ArtifactDetail
from ..widgets import DictTableModel, Page, button, h1, hbox, make_table, muted

CATS = ["contact", "message", "call", "media", "document", "browser", "app", "location", "calendar", "note", "log",
        "device_info", "recovered"]


class SearchPage(Page):
    title = "Search"

    def __init__(self, main):
        super().__init__(main)
        self.page = 1
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.addWidget(h1("Forensic search"))
        box = QGroupBox("Combinable filters")
        g = QGridLayout(box)
        self.text, self.phone, self.email, self.name = QLineEdit(), QLineEdit(), QLineEdit(), QLineEdit()
        self.sha, self.mime, self.conv = QLineEdit(), QLineEdit(), QLineEdit()
        self.deep = QCheckBox("search inside full (encrypted) content - slower")
        self.use_dates = QCheckBox("period")
        self.start, self.end = QDateTimeEdit(), QDateTimeEdit()
        for w in (self.start, self.end):
            w.setCalendarPopup(True)
            w.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.start.setDateTime(QDateTime.currentDateTime().addYears(-1))
        self.end.setDateTime(QDateTime.currentDateTime())
        self.use_geo = QCheckBox("geographic box")
        self.lat0, self.lat1, self.lon0, self.lon1 = (QDoubleSpinBox() for _ in range(4))
        for sp, lo, hi, v in ((self.lat0, -90, 90, 48.8), (self.lat1, -90, 90, 48.9), (self.lon0, -180, 180, 2.3),
                              (self.lon1, -180, 180, 2.4)):
            sp.setRange(lo, hi)
            sp.setDecimals(5)
            sp.setValue(v)
        self.cats = {c: QCheckBox(c) for c in CATS}
        for (lab, w), (r, c) in zip((("Word / phrase", self.text), ("Phone number", self.phone), ("E-mail", self.email),
                                     ("Name", self.name), ("SHA-256", self.sha), ("Document / MIME type", self.mime),
                                     ("Conversation", self.conv)),
                                    ((0, 0), (0, 2), (1, 0), (1, 2), (2, 0), (2, 2), (3, 0))):
            g.addWidget(QLabel(lab), r, c)
            g.addWidget(w, r, c + 1)
        g.addWidget(self.deep, 3, 2, 1, 2)
        g.addLayout(hbox(self.use_dates, self.start, QLabel("->"), self.end), 4, 0, 1, 4)
        g.addLayout(hbox(self.use_geo, QLabel("lat"), self.lat0, self.lat1, QLabel("lon"), self.lon0, self.lon1), 5, 0, 1, 4)
        g.addLayout(hbox(QLabel("Categories:"), *self.cats.values()), 6, 0, 1, 4)
        lay.addWidget(box)
        self.info = QLabel("")
        lay.addLayout(hbox(button("Search", self.run, "Primary"), button("Clear", self.clear), None,
                           button("< Prev", self._prev), self.info, button("Next >", self._next), stretch_end=False))
        split = QSplitter(Qt.Horizontal)
        tabs = QTabWidget()
        self.model = DictTableModel(COLUMNS + [("parser", "Parser"), ("sha256", "SHA-256")])
        self.table = make_table(self.model, 4)
        self.table.setColumnWidth(1, 170)
        self.table.clicked.connect(lambda i: self.detail.show_artifact(self.model.row(i.row())["artifact_id"]))
        tabs.addTab(self.table, "Artefacts")
        self.files = DictTableModel([("evidence", "Evidence"), ("path", "Path"), ("type", "Type"), ("size", "Bytes"),
                                     ("sha256", "SHA-256")])
        tabs.addTab(make_table(self.files, 1), "Evidence files")
        split.addWidget(tabs)
        self.detail = ArtifactDetail(main)
        split.addWidget(self.detail)
        split.setSizes([800, 420])
        lay.addWidget(split, 1)

    def refresh(self):
        pass

    def quick(self, text: str):
        self.clear()
        t = text.strip()
        if len(t) == 64 and all(c in "0123456789abcdefABCDEF" for c in t):
            self.sha.setText(t)
        elif "@" in t and " " not in t:
            self.email.setText(t)
        elif sum(c.isdigit() for c in t) >= 6 and all(c.isdigit() or c in "+ -.()" for c in t):
            self.phone.setText(t)
        else:
            self.text.setText(t)
            self.deep.setChecked(True)
        self.run()

    def clear(self):
        for w in (self.text, self.phone, self.email, self.name, self.sha, self.mime, self.conv):
            w.clear()
        for cb in list(self.cats.values()) + [self.deep, self.use_dates, self.use_geo]:
            cb.setChecked(False)

    def _query(self):
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(self.tz)
        kw = dict(text=self.text.text().strip() or None, deep=self.deep.isChecked(), phone=self.phone.text().strip() or None,
                  email=self.email.text().strip() or None, name=self.name.text().strip() or None,
                  sha256=self.sha.text().strip() or None, mime=self.mime.text().strip() or None,
                  conversation_id=self.conv.text().strip() or None,
                  categories=[c for c, cb in self.cats.items() if cb.isChecked()], page=self.page, page_size=200)
        if self.use_dates.isChecked():
            kw["start"] = self.start.dateTime().toPython().replace(tzinfo=tz)
            kw["end"] = self.end.dateTime().toPython().replace(tzinfo=tz)
        if self.use_geo.isChecked():
            kw.update(min_lat=self.lat0.value(), max_lat=self.lat1.value(), min_lon=self.lon0.value(), max_lon=self.lon1.value())
        return SearchQuery(**kw)

    def run(self, reset=True):
        if not self.needs_case():
            return
        if reset is True:
            self.page = 1
        q = self.guard(self._query)
        if q is None:
            return
        res = self.guard(self.ctx.search.search, self.session, self.case_id, q)
        if res is None:
            return
        self.model.tz = self.tz
        rows = []
        for h in res.hits:
            r = dict(h.__dict__)
            r["source"] = f"{h.source_path} [{h.source_table or '-'}#{h.source_rowid or '-'}]"
            rows.append(r)
        self.model.set_rows(rows)
        self.files.set_rows(res.file_hits)
        self.info.setText(f"{res.total} result(s) - page {res.page}/{res.pages} - {len(res.file_hits)} file match(es)")

    def _prev(self):
        self.page = max(1, self.page - 1)
        self.run(reset=False)

    def _next(self):
        self.page += 1
        self.run(reset=False)
