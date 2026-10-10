"""iOS connector based on documented mechanisms.

* Detection / device information: libimobiledevice ``idevice_id`` and
  ``ideviceinfo`` (requires the device to be unlocked and the host trusted).
* Collection: ``idevicebackup2 backup`` - the official backup protocol.
  If the user enabled backup encryption on the device, the produced backup
  is encrypted and cannot be parsed by this version (reported explicitly).
* Discovery of existing local Finder/iTunes backups.

No jailbreak, exploit or passcode bypass is used or supported.
"""
from __future__ import annotations

import os
import platform
import plistlib
import re
from pathlib import Path

from ..core.errors import ValidationError
from ..ingest.plugins.ios_backup import device_info_from_backup
from .base import DeviceProbe, default_runner, which

UDID_RE = re.compile(r"^[A-Fa-f0-9\-]{24,64}$")

LIMITATIONS = [
    "Logical collection through the iOS backup service: content limited to what iOS includes in backups.",
    "Keychain, Health and some protected data are only included in encrypted backups (not supported).",
    "No file-system or physical extraction; deleted data is not accessible.",
]


def standard_backup_dirs() -> list[Path]:
    home = Path.home()
    cands = []
    if platform.system() == "Darwin":
        cands.append(home / "Library" / "Application Support" / "MobileSync" / "Backup")
    elif platform.system() == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            cands.append(Path(appdata) / "Apple Computer" / "MobileSync" / "Backup")
        cands.append(home / "Apple" / "MobileSync" / "Backup")
    else:
        cands.append(home / ".local" / "share" / "MobileSync" / "Backup")
    return [c for c in cands if c.is_dir()]


def find_local_backups(extra_dirs: list[Path] | None = None) -> list[dict]:
    out = []
    for base in standard_backup_dirs() + [Path(d) for d in (extra_dirs or [])]:
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            if d.is_dir() and (d / "Manifest.db").exists() or d.is_dir() and (d / "Manifest.plist").exists():
                info = device_info_from_backup(d)
                out.append({"path": str(d), **info})
    return out


class IosConnector:
    def __init__(self, runner=default_runner):
        self.runner = runner
        self.idevice_id = which("idevice_id") or "idevice_id"
        self.ideviceinfo = which("ideviceinfo") or "ideviceinfo"
        self.idevicebackup2 = which("idevicebackup2") or "idevicebackup2"

    def available(self) -> bool:
        return self.runner([self.idevice_id, "-l"], timeout=10).returncode in (0,)

    def list_devices(self) -> list[str]:
        r = self.runner([self.idevice_id, "-l"], timeout=15)
        return [l.strip() for l in r.stdout.splitlines() if UDID_RE.match(l.strip())] if r.returncode == 0 else []

    def probe(self, udid: str) -> DeviceProbe:
        if not UDID_RE.match(udid or ""):
            raise ValidationError("Invalid UDID.")
        p = DeviceProbe(platform="ios", serial=udid, manufacturer="Apple", label=udid)
        r = self.runner([self.ideviceinfo, "-u", udid, "-x"], timeout=30)
        if r.returncode != 0:
            p.connection_state = "connected, not paired"
            p.limitations = ["Device not paired/trusted or locked: unlock it and accept 'Trust this computer' "
                             "(with the owner's consent or legal authority)."]
            return p
        try:
            info = plistlib.loads(r.stdout.encode())
        except Exception:
            info = {}
        p.raw["lockdown"] = {k: v for k, v in info.items() if isinstance(v, (str, int, bool))}
        p.model = str(info.get("ProductType", ""))
        p.label = str(info.get("DeviceName", udid))
        p.os_version = f"iOS {info.get('ProductVersion', '?')} ({info.get('BuildVersion', '?')})"
        p.identifiers = {k: str(info[v]) for k, v in (("serial", "SerialNumber"), ("udid", "UniqueDeviceID"),
                                                      ("imei", "InternationalMobileEquipmentIdentity"),
                                                      ("phone_number", "PhoneNumber")) if info.get(v)}
        p.connection_state = "connected, paired"
        p.access_level = "lockdown pairing (logical: device info + backup service)"
        p.limitations = list(LIMITATIONS)
        return p

    def backup(self, udid: str, dest: Path) -> tuple[bool, str]:
        if not UDID_RE.match(udid or ""):
            raise ValidationError("Invalid UDID.")
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        r = self.runner([self.idevicebackup2, "-u", udid, "backup", "--full", str(dest)], timeout=6 * 3600)
        return r.returncode == 0, (r.stderr or r.stdout)[-2000:]
