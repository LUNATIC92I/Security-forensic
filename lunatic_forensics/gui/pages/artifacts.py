from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QListWidget, QListWidgetItem, QSplitter, QTabWidget, QVBoxLayout, QWidget
from PySide6.QtCore import Qt
from ..artifact_view import ArtifactBrowser
from ..widgets import Page, button, h1, hbox, muted

TABS = [("Contacts", ["contact"]), ("Messages", ["message"]), ("Calls", ["call"]), ("Images && videos", ["media"]),
        ("Documents", ["document"]), ("Browser", ["browser"]), ("Applications", ["app"]), ("Locations", ["location"]),
        ("Calendar && notes", ["calendar", "note"]), ("System logs", ["log"]), ("Device info", ["device_info"]),
        ("Deleted / residual (experimental)", ["recovered"])]


class MessagesTab(QWidget):
    """Conversation list + message browser."""

    def __init__(self, main):
        super().__init__()
        self.main = main
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(4, 4, 4, 4)
        ll.addWidget(muted("Conversations"))
        self.convs = QListWidget()
        self.convs.currentItemChanged.connect(self._pick)
        ll.addWidget(self.convs)
        split.addWidget(left)
        self.browser = ArtifactBrowser(main, ["message"])
        split.addWidget(self.browser)
        split.setSizes([260, 1000])
        lay.addWidget(split)

    def reload(self):
        self.convs.blockSignals(True)
        self.convs.clear()
        QListWidgetItem("(all conversations)", self.convs).setData(Qt.UserRole, None)
        if self.main.case_id is not None:
            for cid, n, _last in self.main.guard(self.main.ctx.analysis.conversations, self.main.session,
                                                 self.main.case_id) or []:
                it = QListWidgetItem(f"{cid}  ({n})", self.convs)
                it.setData(Qt.UserRole, cid)
        self.convs.blockSignals(False)
        self.browser.fixed = {}
        self.browser.reload()

    def _pick(self, item, _prev):
        if item is None:
            return
        cid = item.data(Qt.UserRole)
        self.browser.fixed = {"conversation_id": cid} if cid else {}
        self.browser.reload()


class ArtifactsPage(Page):
    title = "Artefacts"

    def __init__(self, main):
        super().__init__(main)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.counts_label = muted("")
        lay.addLayout(hbox(h1("Artefacts"), None, button("Refresh", self.refresh), stretch_end=False))
        lay.addWidget(muted("Values are shown as found in the source ('Original values') and as interpreted by the parser "
                            "('Interpreted values'). Each record links back to its source file, table and row."))
        lay.addWidget(self.counts_label)
        self.tabs = QTabWidget()
        self.browsers = []
        for title, cats in TABS:
            w = MessagesTab(main) if cats == ["message"] else ArtifactBrowser(main, cats)
            self.tabs.addTab(w, title)
            self.browsers.append(w)
        self.tabs.currentChanged.connect(lambda i: self._load(i))
        lay.addWidget(self.tabs, 1)

    def _load(self, i):
        w = self.browsers[i]
        w.reload()

    def refresh(self):
        if self.case_id is None:
            self.counts_label.setText("No case selected.")
        else:
            counts = self.ctx.analysis.category_counts(self.session, self.case_id)
            self.counts_label.setText("  ·  ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "No artefact yet.")
            for i, (title, cats) in enumerate(TABS):
                n = sum(counts.get(c, 0) for c in cats)
                self.tabs.setTabText(i, f"{title} ({n})")
        self._load(self.tabs.currentIndex())
