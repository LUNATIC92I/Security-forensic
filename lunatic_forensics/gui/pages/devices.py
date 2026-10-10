from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLineEdit,
                               QPlainTextEdit, QSplitter, QVBoxLayout, QWidget)

from ...acquisition.adb import CONTENT_URIS, AdbConnector
from ...acquisition.ios import IosConnector, find_local_backups
from ...core.rbac import Perm, has_perm
from ..widgets import DictTableModel, JsonTree, Page, button, confirm, h1, h2, hbox, make_table, muted, selected_rows


class AuthorizationDialog(QDialog):
    def __init__(self, parent, title="Authorisation", with_collection=False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(520)
        f = QFormLayout(self)
        f.addRow(muted("Collection is only allowed under a documented legal authority or with the owner's consent."))
        self.ref = QLineEdit()
        self.ref.setPlaceholderText("Warrant / requisition / consent form reference (required)")
        self.scope = QPlainTextEdit()
        self.scope.setMaximumHeight(70)
        self.scope.setPlaceholderText("Authorised collection scope")
        f.addRow("Authorisation *", self.ref)
        f.addRow("Scope", self.scope)
        self.paths = QLineEdit("/sdcard/DCIM")
        self.content = {k: QCheckBox(k) for k in CONTENT_URIS}
        self.logcat = QCheckBox("logcat buffer")
        self.logcat.setChecked(True)
        if with_collection:
            f.addRow("Shared storage paths (;)", self.paths)
            for cb in self.content.values():
                f.addRow("Content provider", cb)
            f.addRow("", self.logcat)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        f.addRow(bb)


class ManualDeviceDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Register device manually")
        f = QFormLayout(self)
        self.label = QLineEdit()
        self.platform = QComboBox()
        self.platform.addItems(["android", "ios", "other", "unknown"])
        self.manu, self.model, self.os = QLineEdit(), QLineEdit(), QLineEdit()
        self.ident = QLineEdit()
        self.ident.setPlaceholderText("key=value; key=value (e.g. imei=...; serial=...)")
        self.access = QComboBox()
        self.access.setEditable(True)
        self.access.addItems(["none (seized, not examined)", "logical (backup)", "logical (adb shell, no root)",
                              "file system (vendor tool)", "physical image (vendor tool)"])
        self.auth, self.scope = QLineEdit(), QLineEdit()
        for lab, w in (("Label *", self.label), ("Platform", self.platform), ("Manufacturer", self.manu),
                       ("Model", self.model), ("OS version", self.os), ("Identifiers", self.ident),
                       ("Access level", self.access), ("Authorisation *", self.auth), ("Scope", self.scope)):
            f.addRow(lab, w)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def values(self):
        ids = dict(p.split("=", 1) for p in self.ident.text().split(";") if "=" in p)
        return dict(label=self.label.text().strip(), platform=self.platform.currentText(), manufacturer=self.manu.text(),
                    model=self.model.text(), os_version=self.os.text(),
                    identifiers={k.strip(): v.strip() for k, v in ids.items()}, access_level=self.access.currentText(),
                    authorization_ref=self.auth.text().strip(), collection_scope=self.scope.text())


class DevicesPage(Page):
    title = "Devices"

    def __init__(self, main):
        super().__init__(main)
        self.adb = AdbConnector()
        self.ios = IosConnector()
        self.probes = []
        can = has_perm(self.session.role, Perm.ACQUIRE_DEVICE)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.b_detect = button("Detect connected devices", self.detect, "Primary")
        self.b_register = button("Register selected", self.register)
        self.b_collect = button("ADB logical collection...", self.collect)
        self.b_iosbk = button("iOS backup (idevicebackup2)...", self.ios_backup)
        self.b_manual = button("Register manually...", self.manual)
        for b in (self.b_detect, self.b_register, self.b_collect, self.b_iosbk, self.b_manual):
            b.setEnabled(can)
        lay.addLayout(hbox(h1("Devices"), None, self.b_detect, self.b_register, self.b_collect, self.b_iosbk,
                           self.b_manual, stretch_end=False))
        lay.addWidget(muted("Authorised connectors only (USB debugging accepted on the device, iOS pairing / 'Trust this "
                            "computer', local backups). No lock bypass, exploit or protection circumvention is implemented. "
                            "The access level shown is the level actually obtained."))
        split = QSplitter(Qt.Vertical)
        w = QWidget()
        l1 = QVBoxLayout(w)
        l1.setContentsMargins(0, 0, 0, 0)
        l1.addWidget(h2("Detected devices and local backups"))
        self.det_model = DictTableModel([("platform", "Platform"), ("serial", "Serial / UDID / path"), ("label", "Device"),
                                         ("os_version", "OS"), ("connection_state", "Connection"),
                                         ("access_level", "Access level"), ("limitations", "Limitations"),
                                         ("probed_at", "Probed at")])
        self.det_table = make_table(self.det_model, 6)
        l1.addWidget(self.det_table)
        split.addWidget(w)
        w2 = QWidget()
        l2 = QVBoxLayout(w2)
        l2.setContentsMargins(0, 0, 0, 0)
        l2.addWidget(h2("Devices of the investigation"))
        self.model = DictTableModel([("id", "#"), ("label", "Label"), ("platform", "Platform"), ("manufacturer", "Manufacturer"),
                                     ("model", "Model"), ("os_version", "OS"), ("access_level", "Access level"),
                                     ("connection_state", "State"), ("authorization_ref", "Authorisation"),
                                     ("acquired_at", "Acquired")])
        self.table = make_table(self.model, 1)
        self.table.clicked.connect(self._detail)
        l2.addWidget(self.table)
        self.tree = JsonTree()
        l2.addWidget(self.tree)
        split.addWidget(w2)
        lay.addWidget(split, 1)

    def refresh(self):
        if self.case_id is None:
            self.model.set_rows([])
            return
        self.model.tz = self.tz
        self.model.set_rows([d.__dict__ for d in self.ctx.devices.list(self.session, self.case_id)])

    def _detail(self, idx):
        d = self.model.row(idx.row())
        self.tree.show_obj({k: d.get(k) for k in ("label", "platform", "manufacturer", "model", "os_version", "identifiers",
                                                  "access_level", "limitations", "connection_state", "authorization_ref",
                                                  "collection_scope", "acquired_at")})

    def detect(self):
        def job():
            probes, notes = [], []
            if self.adb.available():
                probes += [self.adb.probe(*d) for d in self.adb.list_devices()]
            else:
                notes.append("adb not found (install Android platform-tools or set LUNATIC_ADB).")
            if self.ios.available():
                probes += [self.ios.probe(u) for u in self.ios.list_devices()]
            else:
                notes.append("libimobiledevice tools not found (idevice_id / ideviceinfo).")
            backups = find_local_backups()
            return probes, notes, backups

        def done(res):
            probes, notes, backups = res
            self.probes = probes
            rows = [p.__dict__ for p in probes]
            rows += [{"platform": "ios (local backup)", "serial": b["path"], "label": b.get("device_name", ""),
                      "os_version": b.get("os_version", ""), "connection_state": "offline backup",
                      "access_level": "encrypted backup - not supported" if b.get("is_encrypted") else "importable backup",
                      "limitations": ["Import it from the Evidence page"]} for b in backups]
            self.det_model.set_rows(rows)
            for n in notes:
                self.main.notify(n, "warn")
            if not rows:
                self.main.notify("No device or local backup detected.")
        self.main.run_task("Device detection", job, on_done=done, with_progress=False)

    def _selected_probe(self):
        rows = selected_rows(self.det_table)
        if not rows or rows[0] >= len(self.probes):
            self.main.notify("Select a connected device in the detection list.", "warn")
            return None
        return self.probes[rows[0]]

    def register(self):
        p = self._selected_probe()
        if p is None or not self.needs_case():
            return
        d = AuthorizationDialog(self, "Register device")
        if d.exec():
            self.guard(self.ctx.devices.register_probe, self.session, self.case_id, p, d.ref.text(), d.scope.toPlainText())
            self.refresh()

    def manual(self):
        if not self.needs_case():
            return
        d = ManualDeviceDialog(self)
        if d.exec():
            v = d.values()
            if not v["label"] or not v["authorization_ref"]:
                self.main.notify("Label and authorisation are required.", "warn")
                return
            self.guard(self.ctx.devices.add, self.session, self.case_id, **v)
            self.refresh()

    def collect(self):
        p = self._selected_probe()
        if p is None or not self.needs_case():
            return
        if p.platform != "android" or p.connection_state != "device":
            self.main.notify("ADB collection requires an authorised Android device in state 'device'.", "warn")
            return
        d = AuthorizationDialog(self, "ADB logical collection", with_collection=True)
        if not d.exec() or not d.ref.text().strip():
            return
        paths = [x.strip() for x in d.paths.text().split(";") if x.strip()]
        queries = [k for k, cb in d.content.items() if cb.isChecked()]
        if not confirm(self, "Start collection", f"Collect from {p.label}: properties, packages, "
                                                 f"{', '.join(queries) or 'no content providers'}, paths {paths}?"):
            return
        case_id, ref, scope = self.case_id, d.ref.text(), d.scope.toPlainText()
        staging = self.ctx.config.home / "staging" / f"adb_{p.serial}_{datetime.now().strftime('%Y%m%d%H%M%S')}"

        def job(progress):
            dev_id = self.ctx.devices.register_probe(self.session, case_id, p, ref, scope)
            out = self.adb.collect(p.serial, staging, remote_paths=paths, content_queries=queries,
                                   logcat=d.logcat.isChecked(), progress=progress)
            ev = self.ctx.evidence.import_evidence(self.session, case_id, out, device_id=dev_id,
                                                   acquisition_method="ADB logical collection (no root)",
                                                   tool_name="adb", tool_version=self.adb.version(), progress=progress)
            self.ctx.analysis.run(self.session, ev, progress=progress)
            return ev
        self.main.run_task("ADB collection", job, on_done=lambda _: self.refresh())

    def ios_backup(self):
        p = self._selected_probe()
        if p is None or not self.needs_case():
            return
        if p.platform != "ios" or "paired" not in p.connection_state or "not" in p.connection_state:
            self.main.notify("iOS backup requires a paired (trusted) iOS device.", "warn")
            return
        d = AuthorizationDialog(self, "iOS backup")
        if not d.exec() or not d.ref.text().strip():
            return
        case_id, ref, scope = self.case_id, d.ref.text(), d.scope.toPlainText()
        staging = self.ctx.config.home / "staging" / f"ios_{p.serial[:12]}_{datetime.now().strftime('%Y%m%d%H%M%S')}"

        def job():
            from ...core.errors import ForensicError
            dev_id = self.ctx.devices.register_probe(self.session, case_id, p, ref, scope)
            ok, msg = self.ios.backup(p.serial, staging)
            if not ok:
                raise ForensicError(f"idevicebackup2 failed: {msg[-300:]}")
            folder = next((x for x in staging.iterdir() if x.is_dir()), staging)
            return self.ctx.evidence.import_evidence(self.session, case_id, folder, device_id=dev_id,
                                                     acquisition_method="iOS backup service (idevicebackup2)",
                                                     tool_name="idevicebackup2")
        self.main.run_task("iOS backup", job, on_done=lambda _: self.refresh(), with_progress=False)
