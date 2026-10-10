from __future__ import annotations

import math
import random

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import (QGraphicsEllipseItem, QGraphicsScene, QGraphicsSimpleTextItem, QGraphicsView,
                               QSplitter, QVBoxLayout, QWidget)

from ..theme import COLORS
from ..widgets import DictTableModel, Page, button, h1, hbox, make_table, muted


def force_layout(nodes: list[str], edges: list[tuple[str, str, int]], iterations: int = 200, seed: int = 7):
    rnd = random.Random(seed)
    pos = {n: [rnd.uniform(-300, 300), rnd.uniform(-300, 300)] for n in nodes}
    k = 140.0
    for it in range(iterations):
        disp = {n: [0.0, 0.0] for n in nodes}
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                d = math.hypot(dx, dy) or 0.01
                f = k * k / d
                disp[a][0] += dx / d * f
                disp[a][1] += dy / d * f
                disp[b][0] -= dx / d * f
                disp[b][1] -= dy / d * f
        for a, b, w in edges:
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = math.hypot(dx, dy) or 0.01
            f = d * d / k * (1 + math.log1p(w) * 0.2)
            disp[a][0] -= dx / d * f
            disp[a][1] -= dy / d * f
            disp[b][0] += dx / d * f
            disp[b][1] += dy / d * f
        t = 30 * (1 - it / iterations) + 1
        for n in nodes:
            dx, dy = disp[n]
            d = math.hypot(dx, dy) or 0.01
            pos[n][0] += dx / d * min(d, t)
            pos[n][1] += dy / d * min(d, t)
    return pos


class GraphView(QGraphicsView):
    def __init__(self, on_pick):
        super().__init__()
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.Antialiasing)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setBackgroundBrush(QColor(COLORS["panel"]))
        self.on_pick = on_pick

    def wheelEvent(self, ev):
        f = 1.15 if ev.angleDelta().y() > 0 else 1 / 1.15
        self.scale(f, f)

    def mousePressEvent(self, ev):
        item = self.itemAt(ev.position().toPoint())
        if item is not None and item.data(0):
            self.on_pick(item.data(0))
        super().mousePressEvent(ev)


class RelationsPage(Page):
    title = "Relations"

    def __init__(self, main):
        super().__init__(main)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.addLayout(hbox(h1("Relationship explorer"), None, button("Refresh", self.refresh), stretch_end=False))
        lay.addWidget(muted("Nodes: evidence sources (blue squares) and counterparts (circles, sized by volume). Edge width = "
                            "number of messages and calls observed. Names come from contact records. Wheel to zoom, drag to pan, "
                            "click a counterpart to list its records."))
        split = QSplitter(Qt.Horizontal)
        self.view = GraphView(self._pick)
        split.addWidget(self.view)
        side = QWidget()
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 0)
        self.edge_model = DictTableModel([("label", "Counterpart"), ("weight", "Records"), ("kinds", "By type"),
                                          ("source", "Evidence")])
        self.edges_table = make_table(self.edge_model, 0)
        self.edges_table.doubleClicked.connect(lambda i: self._pick(self.edge_model.row(i.row())["target"]))
        sl.addWidget(self.edges_table)
        self.sel = muted("")
        sl.addWidget(self.sel)
        sl.addWidget(button("Search this identifier", self._search))
        split.addWidget(side)
        split.setSizes([900, 380])
        lay.addWidget(split, 1)
        self.current = None

    def refresh(self):
        sc = self.view.scene()
        sc.clear()
        if self.case_id is None:
            return
        g = self.ctx.correlation.graph(self.session, self.case_id)
        nodes = [n["id"] for n in g["nodes"]]
        labels = {n["id"]: n for n in g["nodes"]}
        edges = [(e["source"], e["target"], e["weight"]) for e in g["edges"]]
        self.edge_model.set_rows([{**e, "label": labels[e["target"]]["label"]} for e in g["edges"]])
        if not nodes:
            sc.addSimpleText("No communication artefacts.").setBrush(QColor(COLORS["muted"]))
            return
        pos = force_layout(nodes, edges, iterations=150 if len(nodes) < 120 else 60)
        vol = {}
        for a, b, w in edges:
            vol[b] = vol.get(b, 0) + w
        mx = max(w for *_, w in edges) if edges else 1
        for a, b, w in edges:
            pen = QPen(QColor(COLORS["graphite"]), 1 + 5 * w / mx)
            sc.addLine(pos[a][0], pos[a][1], pos[b][0], pos[b][1], pen)
        for n in nodes:
            x, y = pos[n]
            info = labels[n]
            if info["type"] == "source":
                item = sc.addRect(x - 12, y - 12, 24, 24, QPen(QColor(COLORS["silver"])), QBrush(QColor(COLORS["accent2"])))
            else:
                r = 6 + min(18, 3 * math.log1p(vol.get(n, 1)) * 2)
                item = QGraphicsEllipseItem(x - r, y - r, 2 * r, 2 * r)
                item.setBrush(QBrush(QColor(COLORS["accent"])))
                item.setPen(QPen(QColor(COLORS["silver"]), 1))
                sc.addItem(item)
            item.setData(0, n)
            item.setToolTip(info["label"])
            t = QGraphicsSimpleTextItem(info["label"][:40])
            t.setBrush(QColor(COLORS["text"]))
            t.setPos(x + 14, y - 8)
            sc.addItem(t)
        self.view.fitInView(sc.itemsBoundingRect().adjusted(-60, -60, 60, 60), Qt.KeepAspectRatio)

    def _pick(self, node_id: str):
        self.current = node_id
        self.sel.setText(f"Selected: <b>{node_id}</b>")

    def _search(self):
        if self.current and not self.current.startswith("ev:"):
            p = self.main.go("SearchPage")
            if p:
                p.quick(self.current)
