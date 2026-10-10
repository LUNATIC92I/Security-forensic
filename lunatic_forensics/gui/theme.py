"""Visual identity: deep black, graphite, silver and electric blue."""

COLORS = {
    "bg": "#07090c", "panel": "#0f1318", "panel2": "#151a21", "line": "#232a33", "graphite": "#2a313a",
    "text": "#d9dee5", "muted": "#8a95a3", "silver": "#c5ccd6", "accent": "#2f8cff", "accent2": "#1f6fd6",
    "ok": "#2bb673", "warn": "#f5a623", "bad": "#ff4d4f", "hyp": "#d9a21b",
}

QSS = """
* { font-family: "Segoe UI", "Inter", "Roboto", "Helvetica Neue", Arial, sans-serif; font-size: 10pt; }
QMainWindow, QDialog, QWidget#Page { background: %(bg)s; color: %(text)s; }
QWidget { color: %(text)s; }
QLabel#H1 { font-size: 17pt; font-weight: 600; color: %(silver)s; }
QLabel#H2 { font-size: 11.5pt; font-weight: 600; color: %(accent)s; padding-top: 6px; }
QLabel#Muted { color: %(muted)s; }
QLabel#Brand { font-size: 12.5pt; font-weight: 700; letter-spacing: 2px; color: %(silver)s; padding: 14px 12px 2px 14px; }
QLabel#BrandSub { color: %(accent)s; font-size: 8pt; letter-spacing: 3px; padding: 0 12px 12px 14px; }
QFrame#Sidebar { background: %(panel)s; border-right: 1px solid %(line)s; }
QFrame#TopBar { background: %(panel)s; border-bottom: 1px solid %(line)s; }
QFrame#Card { background: %(panel2)s; border: 1px solid %(line)s; border-radius: 8px; }
QLabel#CardValue { font-size: 20pt; font-weight: 600; color: %(silver)s; }
QLabel#CardTitle { color: %(muted)s; font-size: 8.5pt; text-transform: uppercase; letter-spacing: 1px; }
QListWidget#Nav { background: transparent; border: none; outline: 0; }
QListWidget#Nav::item { padding: 8px 14px; border-left: 3px solid transparent; color: %(muted)s; }
QListWidget#Nav::item:hover { background: %(panel2)s; color: %(text)s; }
QListWidget#Nav::item:selected { background: #0d1f36; color: %(silver)s; border-left: 3px solid %(accent)s; }
QPushButton { background: %(graphite)s; border: 1px solid #364050; border-radius: 5px; padding: 5px 12px; color: %(text)s; }
QPushButton:hover { border-color: %(accent)s; }
QPushButton:pressed { background: #1b2230; }
QPushButton:disabled { color: #5b6573; border-color: %(line)s; background: %(panel)s; }
QPushButton#Primary { background: %(accent2)s; border: 1px solid %(accent)s; color: white; font-weight: 600; }
QPushButton#Primary:hover { background: %(accent)s; }
QPushButton#Danger { background: #3a1517; border-color: #7a2a2d; }
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateTimeEdit {
    background: %(panel)s; border: 1px solid %(line)s; border-radius: 4px; padding: 4px 6px;
    selection-background-color: %(accent2)s; }
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus { border-color: %(accent)s; }
QComboBox QAbstractItemView { background: %(panel)s; selection-background-color: %(accent2)s; }
QTableView, QTreeWidget, QTreeView, QListWidget { background: %(panel)s; alternate-background-color: #11161c;
    border: 1px solid %(line)s; gridline-color: %(line)s; selection-background-color: #12345c; selection-color: white; }
QHeaderView::section { background: %(panel2)s; color: %(muted)s; border: none; border-right: 1px solid %(line)s;
    border-bottom: 1px solid %(line)s; padding: 4px 6px; font-weight: 600; }
QTabWidget::pane { border: 1px solid %(line)s; top: -1px; }
QTabBar::tab { background: %(panel)s; color: %(muted)s; padding: 6px 12px; border: 1px solid %(line)s; border-bottom: none; }
QTabBar::tab:selected { background: %(panel2)s; color: %(silver)s; border-top: 2px solid %(accent)s; }
QGroupBox { border: 1px solid %(line)s; border-radius: 6px; margin-top: 12px; padding-top: 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: %(accent)s; }
QStatusBar { background: %(panel)s; border-top: 1px solid %(line)s; color: %(muted)s; }
QProgressBar { background: %(panel)s; border: 1px solid %(line)s; border-radius: 4px; text-align: center; height: 14px; }
QProgressBar::chunk { background: %(accent)s; border-radius: 3px; }
QSplitter::handle { background: %(line)s; }
QScrollBar:vertical { background: %(bg)s; width: 10px; } QScrollBar::handle:vertical { background: %(graphite)s; border-radius: 4px; min-height: 24px; }
QScrollBar:horizontal { background: %(bg)s; height: 10px; } QScrollBar::handle:horizontal { background: %(graphite)s; border-radius: 4px; min-width: 24px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QMenu { background: %(panel2)s; border: 1px solid %(line)s; } QMenu::item:selected { background: %(accent2)s; }
QToolTip { background: %(panel2)s; color: %(text)s; border: 1px solid %(accent)s; }
QCheckBox::indicator { width: 14px; height: 14px; }
""" % COLORS


def apply(app) -> None:
    from PySide6.QtGui import QColor, QPalette
    app.setStyle("Fusion")
    pal = QPalette()
    for role, key in ((QPalette.Window, "bg"), (QPalette.Base, "panel"), (QPalette.AlternateBase, "panel2"),
                      (QPalette.Text, "text"), (QPalette.WindowText, "text"), (QPalette.Button, "graphite"),
                      (QPalette.ButtonText, "text"), (QPalette.Highlight, "accent2"), (QPalette.ToolTipBase, "panel2"),
                      (QPalette.ToolTipText, "text"), (QPalette.PlaceholderText, "muted")):
        pal.setColor(role, QColor(COLORS[key]))
    pal.setColor(QPalette.HighlightedText, QColor("white"))
    app.setPalette(pal)
    app.setStyleSheet(QSS)
