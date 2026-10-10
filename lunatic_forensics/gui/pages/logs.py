from __future__ import annotations

from PySide6.QtGui import QColor, QTextCharFormat
from PySide6.QtWidgets import QComboBox, QFileDialog, QPlainTextEdit, QVBoxLayout

from ..theme import COLORS
from ..widgets import Page, button, h1, hbox, muted

LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}


class LogsPage(Page):
    title = "Technical log"

    def __init__(self, main):
        super().__init__(main)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.level = QComboBox()
        self.level.addItems(["INFO", "WARNING", "ERROR", "DEBUG"])
        lay.addLayout(hbox(h1("Technical log console"), None, self.level, button("Clear", lambda: self.view.clear()),
                           button("Save...", self.save), stretch_end=False))
        lay.addWidget(muted(f"Live application log. A rotating copy is kept in {self.ctx.config.logs_dir}. "
                            "Messages never contain evidence content or secrets."))
        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(20000)
        self.view.setStyleSheet("font-family: Consolas, Menlo, monospace; font-size: 9pt;")
        lay.addWidget(self.view, 1)
        main.log_handler.bridge.record.connect(self._append)

    def _append(self, level: str, text: str):
        if LEVELS.get(level, 20) < LEVELS.get(self.level.currentText(), 20):
            return
        color = {"WARNING": COLORS["warn"], "ERROR": COLORS["bad"], "CRITICAL": COLORS["bad"]}.get(level, COLORS["text"])
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cur = self.view.textCursor()
        cur.movePosition(cur.MoveOperation.End)
        cur.insertText(text + "\n", fmt)
        self.view.setTextCursor(cur)

    def save(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save log", "lunatic_log.txt")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.view.toPlainText())

    def refresh(self):
        pass
