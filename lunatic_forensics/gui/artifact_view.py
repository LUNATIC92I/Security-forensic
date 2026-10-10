"""Artefact list + detail panel shared by several pages."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QImageReader, QPixmap
from PySide6.QtWidgets import (QCheckBox, QHBoxLayout, QLabel, QLineEdit, QSplitter, QTabWidget, QVBoxLayout,
                               QWidget)

from ..core.timeutils import to_display
from ..services.search_service import SearchQuery
from .widgets import DictTableModel, JsonTree, button, make_table, muted, selected_rows

PREVIEW_TYPES = {"jpeg", "png", "gif", "bmp", "webp"}
MAX_PREVIEW_BYTES = 50 * 1024 * 1024

COLUMNS = [("artifact_id", "#"), ("timestamp", "Time"), ("subtype", "Type"), ("direction", "Dir."),
           ("summary", "Summary"), ("evidence_uid", "Evidence"), ("source", "Source (file [table#row])")]


class ArtifactDetail(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.current = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.head = QLabel("Select an artefact.")
        self.head.setWordWrap(True)
        self.head.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.head)
        self.basket_btn = button("Add to finding basket", self._basket)
        self.basket_btn.setEnabled(False)
        lay.addWidget(self.basket_btn)
        self.tabs = QTabWidget()
        self.interp = JsonTree()
        self.raw = JsonTree()
        self.preview = QLabel("No preview")
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setMinimumHeight(160)
        self.tabs.addTab(self.interp, "Interpreted values")
        self.tabs.addTab(self.raw, "Original values (source)")
        self.tabs.addTab(self.preview, "Secure preview")
        lay.addWidget(self.tabs, 1)

    def show_artifact(self, artifact_id: int):
        a = self.main.guard(self.main.ctx.analysis.artifact, self.main.session, artifact_id)
        if a is None:
            return
        self.current = a
        tz = self.main.case_tz
        flag = " <span style='color:#f5a623'>[RECOVERED - experimental, confidence %.1f]</span>" % (a.confidence or 0) \
            if a.is_recovered else ""
        loc = ""
        if a.latitude is not None:
            loc = f"<br>Location: {a.latitude:.6f}, {a.longitude:.6f} (<b>{a.location_kind}</b>)"
        self.head.setText(
            f"<b>#{a.id} {a.category}/{a.subtype}</b>{flag}<br>{a.summary}<br>"
            f"Time: {to_display(a.timestamp_utc, tz) or '-'} &middot; raw <code>{a.timestamp_raw or '-'}</code> "
            f"&middot; decoding: {a.timestamp_method or '-'}<br>"
            f"Source: <code>{a.source_path}</code> [{a.source_table or '-'} # {a.source_rowid or '-'}]<br>"
            f"Parser: {a.parser_name} {a.parser_version}" + (f" &middot; SHA-256 <code>{a.sha256}</code>" if a.sha256 else "") + loc)
        data = a.data or {}
        self.interp.show_obj(data.get("interpreted", {}))
        self.raw.show_obj(data.get("raw", {}))
        self.basket_btn.setEnabled(True)
        self._preview(a)

    def _preview(self, a):
        self.preview.setPixmap(QPixmap())
        self.preview.setText("No preview available for this artefact.")
        if a.category not in ("media", "recovered") or not a.evidence_file_id and not (a.data or {}).get("interpreted", {}).get("carved_path"):
            return
        if a.subtype not in PREVIEW_TYPES and a.subtype not in ("carved_jpeg", "carved_png"):
            self.preview.setText("Preview limited to still images (JPEG, PNG, GIF, BMP, WEBP).")
            return
        path = (a.data or {}).get("interpreted", {}).get("carved_path")
        if not path:
            path = self.main.guard(self.main.ctx.evidence.working_file_path, self.main.session, a.evidence_file_id)
        if not path:
            return
        from pathlib import Path
        p = Path(path)
        if not p.exists() or p.stat().st_size > MAX_PREVIEW_BYTES:
            self.preview.setText("File too large or missing for preview.")
            return
        reader = QImageReader(str(p))
        reader.setAllocationLimit(256)  # MB - protection against decompression bombs
        size = reader.size()
        if size.isValid() and size.width() * size.height() > 100_000_000:
            self.preview.setText("Image dimensions too large for safe preview.")
            return
        reader.setAutoTransform(True)
        img = reader.read()
        if img.isNull():
            self.preview.setText(f"Image could not be decoded ({reader.errorString()}).")
            return
        self.preview.setPixmap(QPixmap.fromImage(img).scaled(420, 320, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def _basket(self):
        if self.current is not None:
            self.main.basket.add(self.current.id)
            self.main.notify(f"Artefact #{self.current.id} added to the finding basket ({len(self.main.basket)}).")


class ArtifactBrowser(QWidget):
    """Paged artefact table filtered by categories, with a text filter and a detail panel."""

    def __init__(self, main, categories: list[str], extra_filter: bool = False):
        super().__init__()
        self.main = main
        self.categories = categories
        self.page = 1
        self.page_size = 200
        self.fixed: dict = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        bar = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter (text, name, identifier, path)...")
        self.filter.returnPressed.connect(self.reload)
        self.deep = QCheckBox("deep (content)")
        self.recovered = QCheckBox("include recovered")
        self.recovered.setChecked("recovered" in categories)
        bar.addWidget(self.filter, 1)
        bar.addWidget(self.deep)
        if "recovered" not in categories:
            bar.addWidget(self.recovered)
        bar.addWidget(button("Apply", self.reload))
        self.prev = button("<", self._prev)
        self.next = button(">", self._next)
        self.info = QLabel("")
        bar.addWidget(self.prev)
        bar.addWidget(self.info)
        bar.addWidget(self.next)
        lay.addLayout(bar)
        split = QSplitter(Qt.Horizontal)
        self.model = DictTableModel(COLUMNS)
        self.table = make_table(self.model, 4)
        self.table.setColumnWidth(1, 170)
        self.table.clicked.connect(self._clicked)
        split.addWidget(self.table)
        self.detail = ArtifactDetail(main)
        split.addWidget(self.detail)
        split.setSizes([700, 420])
        lay.addWidget(split, 1)

    def reload(self, reset_page: bool = True):
        if reset_page is True:
            self.page = 1
        if self.main.case_id is None:
            self.model.set_rows([])
            self.info.setText("no case")
            return
        q = SearchQuery(text=self.filter.text().strip() or None, deep=self.deep.isChecked(), categories=self.categories,
                        include_recovered=self.recovered.isChecked(), page=self.page, page_size=self.page_size, **self.fixed)
        res = self.main.guard(self.main.ctx.search.search, self.main.session, self.main.case_id, q)
        if res is None:
            return
        self.model.tz = self.main.case_tz
        rows = []
        for h in res.hits:
            r = dict(h.__dict__)
            r["source"] = f"{h.source_path} [{h.source_table or '-'}#{h.source_rowid or '-'}]"
            if h.category in ("recovered",):
                r["_color"] = "#f5a623"
            rows.append(r)
        self.model.set_rows(rows)
        self.info.setText(f"{res.total} rec. - p{res.page}/{res.pages}")
        self.prev.setEnabled(self.page > 1)
        self.next.setEnabled(self.page < res.pages)

    def _prev(self):
        self.page = max(1, self.page - 1)
        self.reload(reset_page=False)

    def _next(self):
        self.page += 1
        self.reload(reset_page=False)

    def _clicked(self, idx):
        self.detail.show_artifact(self.model.row(idx.row())["artifact_id"])

    def selected_ids(self) -> list[int]:
        return [self.model.row(i)["artifact_id"] for i in selected_rows(self.table)]
