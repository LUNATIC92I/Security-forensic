"""Acquisition connectors with simulated tool output (no device required)."""
import json
import plistlib

import pytest

from lunatic_forensics.acquisition.adb import AdbConnector
from lunatic_forensics.acquisition.base import CommandResult
from lunatic_forensics.acquisition.ios import IosConnector, find_local_backups
from lunatic_forensics import synthetic as S
from lunatic_forensics.core.errors import ValidationError

GETPROP = "[ro.product.manufacturer]: [SyntheticMobile]\n[ro.product.model]: [SM-TEST1]\n" \
          "[ro.build.version.release]: [14]\n[ro.build.version.sdk]: [34]\n[ro.serialno]: [SYNTH0001]\n" \
          "[ro.crypto.state]: [encrypted]\n[ro.crypto.type]: [file]\n"


class FakeAdb:
    def __init__(self):
        self.calls = []

    def __call__(self, args, timeout=60):
        self.calls.append(args)
        cmd = args[1:]
        if cmd == ["version"]:
            return CommandResult(args, 0, "Android Debug Bridge version 1.0.41\n", "")
        if cmd == ["devices", "-l"]:
            return CommandResult(args, 0, "List of devices attached\nSYNTH0001 device usb:1-1 model:SM_TEST1\n"
                                          "SYNTH0002 unauthorized usb:1-2\nSYNTH0003 no permissions (udev)\n", "")
        if "getprop" in cmd:
            return CommandResult(args, 0, GETPROP, "")
        if cmd[-1] == "id":
            return CommandResult(args, 0, "uid=2000(shell) gid=2000(shell)\n", "")
        if "pm" in cmd:
            return CommandResult(args, 0, "package:/data/app/x/base.apk=com.whatsapp  installer=com.android.vending\n", "")
        if "content" in cmd:
            return CommandResult(args, 0, "Error: Permission Denial: reading provider\n", "")
        if "logcat" in cmd:
            return CommandResult(args, 0, "03-15 10:55:01.123  1234  1250 I Tag: msg\n", "")
        if "pull" in cmd:
            return CommandResult(args, 0, "1 file pulled\n", "")
        return CommandResult(args, 1, "", "unexpected")


def test_adb_list_and_probe():
    adb = AdbConnector(runner=FakeAdb(), adb_path="adb")
    devs = adb.list_devices()
    assert [(d[0], d[1]) for d in devs] == [("SYNTH0001", "device"), ("SYNTH0002", "unauthorized"),
                                            ("SYNTH0003", "no permissions")]
    p = adb.probe(*devs[0])
    assert p.manufacturer == "SyntheticMobile" and p.model == "SM-TEST1"
    assert p.access_level == "adb shell (uid shell, no root)"
    assert any("sandboxes" in l for l in p.limitations) and any("encryption active" in l for l in p.limitations)
    u = adb.probe(*devs[1])
    assert u.access_level == "none" and "authorisation pending" in u.limitations[0]


def test_adb_collect_and_restrictions(tmp_path):
    fake = FakeAdb()
    adb = AdbConnector(runner=fake, adb_path="adb")
    out = adb.collect("SYNTH0001", tmp_path / "acq", remote_paths=["/sdcard/DCIM"], content_queries=["sms"])
    m = json.loads((out / "acquisition_manifest.json").read_text())
    assert m["method"].startswith("ADB logical") and len(m["commands"]) >= 5
    assert any("refused by the OS" in l for l in m["limitations"])
    assert (out / "adb" / "getprop.txt").read_text() == GETPROP
    assert all(not isinstance(a, str) for a in fake.calls)   # argument lists only (no shell strings)
    with pytest.raises(ValidationError):
        adb.collect("SYNTH0001", tmp_path / "acq2", remote_paths=["/data/data/com.whatsapp"])
    with pytest.raises(ValidationError):
        adb.collect("SYNTH0001", tmp_path / "acq3", remote_paths=["/sdcard/../data"])
    with pytest.raises(ValidationError):
        adb.probe("bad;serial && rm -rf /")


def test_adb_collection_imports_and_parses(ctx, users, case_id, tmp_path):
    out = AdbConnector(runner=FakeAdb(), adb_path="adb").collect("SYNTH0001", tmp_path / "acq")
    ev = ctx.evidence.import_evidence(users["inv"], case_id, out, acquisition_method="ADB logical collection")
    ctx.analysis.run(users["inv"], ev)
    counts = ctx.analysis.category_counts(users["inv"], case_id)
    assert counts.get("device_info") == 1 and counts.get("app") >= 1 and counts.get("log") == 1


def test_register_probe_requires_authorization(ctx, users, case_id):
    p = AdbConnector(runner=FakeAdb(), adb_path="adb").probe("SYNTH0001")
    with pytest.raises(ValidationError):
        ctx.devices.register_probe(users["inv"], case_id, p, "  ", "scope")
    did = ctx.devices.register_probe(users["inv"], case_id, p, "Consent form #42", "Shared storage only")
    d = ctx.devices.list(users["inv"], case_id)[0]
    assert d.id == did and d.access_level.startswith("adb shell") and d.identifiers["serial"] == "SYNTH0001"
    assert d.acquired_at is not None


def test_ios_probe(tmp_path):
    info = plistlib.dumps({"DeviceName": "iPhone synth", "ProductType": "iPhone15,2", "ProductVersion": "17.4",
                           "BuildVersion": "21E", "SerialNumber": "S1", "UniqueDeviceID": "a" * 40}).decode()

    def runner(args, timeout=60):
        if args[0].endswith("idevice_id"):
            return CommandResult(args, 0, "a" * 40 + "\n", "")
        if args[0].endswith("ideviceinfo"):
            return CommandResult(args, 0, info, "")
        return CommandResult(args, 1, "", "")
    ios = IosConnector(runner=runner)
    assert ios.list_devices() == ["a" * 40]
    p = ios.probe("a" * 40)
    assert p.label == "iPhone synth" and p.os_version.startswith("iOS 17.4") and p.connection_state == "connected, paired"
    locked = IosConnector(runner=lambda a, timeout=60: CommandResult(a, 1, "", "ERROR: Could not connect to lockdownd"))
    lp = locked.probe("b" * 40)
    assert lp.access_level == "none" and "Trust this computer" in lp.limitations[0]


def test_find_local_backups(tmp_path):
    S.ios_backup(tmp_path / "Backup" / "00008110")
    found = find_local_backups([tmp_path / "Backup"])
    assert found and found[0]["device_name"] == "iPhone synthetique" and found[0]["is_encrypted"] is False
