from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QGraphicsScene, QGraphicsView, QSplitter, QVBoxLayout,
                               QWidget)

from ..artifact_view import ArtifactDetail
from ..theme import COLORS
from ..widgets import DictTableModel, Page, button, h1, hbox, make_table, muted

KIND_COLOR = {"recorded": COLORS["accent"], "estimated": COLORS["warn"]}


class MapCanvas(QGraphicsView):
    def __init__(self, on_pick):
        super().__init__()
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.Antialiasing)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setBackgroundBrush(QColor("#0a0e13"))
        self.on_pick = on_pick

    def wheelEvent(self, ev):
        f = 1.2 if ev.angleDelta().y() > 0 else 1 / 1.2
        self.scale(f, f)

    def mousePressEvent(self, ev):
        it = self.itemAt(ev.position().toPoint())
        if it is not None and it.data(0):
            self.on_pick(int(it.data(0)))
        super().mousePressEvent(ev)


class MapPage(Page):
    """Offline geographic plot (equirectangular projection, no tile download)."""

    title = "Map"

    def __init__(self, main):
        super().__init__(main)
        self.points = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.show_est = QCheckBox("show estimated locations")
        self.show_est.setChecked(True)
        self.show_est.stateChanged.connect(lambda _: self.refresh())
        lay.addLayout(hbox(h1("Geolocation"), None, self.show_est, button("Export GeoJSON", self.export_geojson),
                           button("Export KML", self.export_kml), button("Refresh", self.refresh), stretch_end=False))
        lay.addWidget(muted("Blue = coordinates recorded in the source (GPS/EXIF/app records). Orange = locations estimated "
                            "by the provider (Wi-Fi/cell, inferred paths) or explicitly marked as estimated. Offline by design: "
                            "no basemap tiles are downloaded; export to GeoJSON/KML for use in a validated GIS."))
        split = QSplitter(Qt.Horizontal)
        self.canvas = MapCanvas(lambda aid: self.detail.show_artifact(aid))
        split.addWidget(self.canvas)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.model = DictTableModel([("artifact_id", "#"), ("timestamp", "Time"), ("category", "Source type"),
                                     ("kind", "Kind"), ("lat", "Lat"), ("lon", "Lon"), ("summary", "Summary")])
        self.table = make_table(self.model, 6)
        self.table.clicked.connect(lambda i: self.detail.show_artifact(self.model.row(i.row())["artifact_id"]))
        rl.addWidget(self.table, 1)
        self.detail = ArtifactDetail(main)
        rl.addWidget(self.detail, 1)
        split.addWidget(right)
        split.setSizes([750, 500])
        lay.addWidget(split, 1)

    def refresh(self):
        sc = self.canvas.scene()
        sc.clear()
        self.points = []
        if self.case_id is None:
            return
        for a in self.ctx.analysis.geolocated(self.session, self.case_id, self.show_est.isChecked()):
            self.points.append({"artifact_id": a.id, "timestamp": a.timestamp_utc, "category": a.category,
                                "kind": a.location_kind or "recorded", "lat": a.latitude, "lon": a.longitude,
                                "summary": a.summary})
        self.model.tz = self.tz
        self.model.set_rows(self.points)
        if not self.points:
            sc.addSimpleText("No geolocated artefact.").setBrush(QColor(COLORS["muted"]))
            return
        lats = [p["lat"] for p in self.points]
        lons = [p["lon"] for p in self.points]
        pad = max(0.002, (max(lats) - min(lats)) * 0.15, (max(lons) - min(lons)) * 0.15)
        la0, la1, lo0, lo1 = min(lats) - pad, max(lats) + pad, min(lons) - pad, max(lons) + pad
        W = 1000.0
        scale = W / (lo1 - lo0)
        H = (la1 - la0) * scale

        def xy(lat, lon):
            return (lon - lo0) * scale, (la1 - lat) * scale

        grid = QPen(QColor(COLORS["line"]), 0)
        steps = 6
        for i in range(steps + 1):
            lat = la0 + (la1 - la0) * i / steps
            lon = lo0 + (lo1 - lo0) * i / steps
            x0, y = xy(lat, lo0)
            sc.addLine(0, y, W, y, grid)
            if i:
                t = sc.addSimpleText(f"{lat:.4f}")
                t.setBrush(QColor(COLORS["muted"]))
                t.setPos(2, y - 14)
            x, _ = xy(la0, lon)
            sc.addLine(x, 0, x, H, grid)
            t = sc.addSimpleText(f"{lon:.4f}")
            t.setBrush(QColor(COLORS["muted"]))
            t.setPos(x + 2, H - 14)
        ordered = sorted([p for p in self.points if p["timestamp"]], key=lambda p: p["timestamp"])
        path_pen = QPen(QColor(COLORS["graphite"]), 1, Qt.DashLine)
        for a, b in zip(ordered, ordered[1:]):
            (x1, y1), (x2, y2) = xy(a["lat"], a["lon"]), xy(b["lat"], b["lon"])
            sc.addLine(x1, y1, x2, y2, path_pen)
        for p in self.points:
            x, y = xy(p["lat"], p["lon"])
            col = QColor(KIND_COLOR.get(p["kind"], COLORS["accent"]))
            r = 7 if p["kind"] == "recorded" else 9
            pen = QPen(QColor(COLORS["silver"]), 1, Qt.SolidLine if p["kind"] == "recorded" else Qt.DashLine)
            it = sc.addEllipse(x - r, y - r, 2 * r, 2 * r, pen, QBrush(col))
            it.setData(0, p["artifact_id"])
            it.setToolTip(f"#{p['artifact_id']} {p['category']} ({p['kind']})\n{p['summary']}")
        self.canvas.fitInView(sc.itemsBoundingRect().adjusted(-30, -30, 30, 30), Qt.KeepAspectRatio)

    def export_geojson(self):
        if not self.points:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export GeoJSON", "locations.geojson", "GeoJSON (*.geojson)")
        if not path:
            return
        feats = [{"type": "Feature", "geometry": {"type": "Point", "coordinates": [p["lon"], p["lat"]]},
                  "properties": {"artifact_id": p["artifact_id"], "time_utc": p["timestamp"].isoformat() if p["timestamp"] else None,
                                 "kind": p["kind"], "category": p["category"], "summary": p["summary"]}} for p in self.points]
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"type": "FeatureCollection", "features": feats}, f, ensure_ascii=False, indent=1)
        self.ctx.audit.log("export.geojson", self.session, case_id=self.case_id, details={"points": len(feats), "path": path})
        self.main.notify(f"{len(feats)} points exported.")

    def export_kml(self):
        if not self.points:
            return
        from xml.sax.saxutils import escape
        path, _ = QFileDialog.getSaveFileName(self, "Export KML", "locations.kml", "KML (*.kml)")
        if not path:
            return
        marks = "".join(
            f"<Placemark><name>#{p['artifact_id']} ({p['kind']})</name><description>{escape(p['summary'])}</description>"
            + (f"<TimeStamp><when>{p['timestamp'].isoformat()}</when></TimeStamp>" if p["timestamp"] else "")
            + f"<Point><coordinates>{p['lon']},{p['lat']},0</coordinates></Point></Placemark>" for p in self.points)
        with open(path, "w", encoding="utf-8") as f:
            f.write(f'<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2"><Document>{marks}</Document></kml>')
        self.ctx.audit.log("export.kml", self.session, case_id=self.case_id, details={"points": len(self.points), "path": path})
        self.main.notify(f"{len(self.points)} points exported.")
