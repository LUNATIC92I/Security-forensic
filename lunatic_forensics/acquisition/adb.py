"""Android Debug Bridge connector (non-root logical collection).

Prerequisites: platform-tools ``adb`` installed, USB debugging enabled **by the
device owner or with legal authority**, and the computer's RSA key accepted on
the device. What can be collected without root depends on Android version,
OEM and permissions:

* device properties (``getprop``), installed packages (``pm list packages``)
* shared storage files the shell user can read (``adb pull /sdcard/...``)
* content providers the shell user may query (``content query``) - often
  restricted on recent Android versions; failures are recorded, not hidden
* ``logcat`` buffer

Application sandboxes (``/data/data``) are **not** accessible without root and
the connector never attempts to obtain root.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .. import __app_name__, __version__
from ..core.errors import ValidationError
from ..core.timeutils import utcnow
from .base import CommandResult, DeviceProbe, default_runner, which

SERIAL_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
REMOTE_PATH_RE = re.compile(r"^/(sdcard|storage/emulated/0|storage/self/primary)(/[^\x00]*)?$")

STATE_MESSAGES = {
    "unauthorized": "USB debugging authorisation pending: the RSA fingerprint must be accepted on the device.",
    "offline": "Device offline: reconnect the cable or restart adb.",
    "no permissions": "Host lacks USB permissions (udev rules on Linux).",
    "recovery": "Device in recovery mode: logical collection not available.",
    "sideload": "Device in sideload mode: logical collection not available.",
    "bootloader": "Device in bootloader mode: no adb access.",
}

BASE_LIMITATIONS = [
    "Non-root ADB session: application sandboxes (/data/data) are not accessible.",
    "'adb backup' is deprecated (Android 12+) and apps may opt out; not used by default.",
    "IMEI/hardware identifiers are not readable via getprop on Android 10+.",
    "Deleted data and unallocated space are not accessible through ADB logical collection.",
]

CONTENT_URIS = {"sms": "content://sms", "calls": "content://call_log/calls",
                "contacts": "content://com.android.contacts/data/phones"}


class AdbConnector:
    def __init__(self, runner=default_runner, adb_path: str | None = None):
        self.runner = runner
        self.adb = adb_path or which("adb", "LUNATIC_ADB") or "adb"

    def available(self) -> bool:
        return self.runner([self.adb, "version"], timeout=10).returncode == 0

    def version(self) -> str:
        r = self.runner([self.adb, "version"], timeout=10)
        return r.stdout.splitlines()[0].strip() if r.returncode == 0 and r.stdout else "unknown"

    def _check_serial(self, serial: str) -> None:
        if not SERIAL_RE.match(serial or ""):
            raise ValidationError("Invalid device serial.")

    def shell(self, serial: str, *cmd: str, timeout: int = 60) -> CommandResult:
        self._check_serial(serial)
        return self.runner([self.adb, "-s", serial, "shell", *cmd], timeout=timeout)

    def list_devices(self) -> list[tuple[str, str, dict]]:
        r = self.runner([self.adb, "devices", "-l"], timeout=15)
        out = []
        if r.returncode != 0:
            return out
        for line in r.stdout.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            serial = parts[0]
            rest = parts[1:]
            state = rest[0] if rest else "unknown"
            if state == "no" and len(rest) > 1 and rest[1] == "permissions":
                state = "no permissions"
            attrs = dict(p.split(":", 1) for p in rest[1:] if ":" in p)
            out.append((serial, state, attrs))
        return out

    def probe(self, serial: str, state: str = "device", attrs: dict | None = None) -> DeviceProbe:
        self._check_serial(serial)
        p = DeviceProbe(platform="android", serial=serial, connection_state=state,
                        label=(attrs or {}).get("model", serial))
        if state != "device":
            p.access_level = "none"
            p.limitations = [STATE_MESSAGES.get(state, f"Device state '{state}': no access.")]
            return p
        r = self.shell(serial, "getprop", timeout=30)
        props = dict(re.findall(r"^\[([^\]]+)\]: \[(.*)\]$", r.stdout, flags=re.M)) if r.returncode == 0 else {}
        p.raw["getprop"] = props
        p.manufacturer = props.get("ro.product.manufacturer", "")
        p.model = props.get("ro.product.model", "")
        p.label = f"{p.manufacturer} {p.model}".strip() or serial
        p.os_version = f"Android {props.get('ro.build.version.release', '?')} (SDK {props.get('ro.build.version.sdk', '?')}," \
                       f" patch {props.get('ro.build.version.security_patch', '?')})"
        p.identifiers = {k: v for k, v in {"serial": props.get("ro.serialno") or serial,
                                           "fingerprint": props.get("ro.build.fingerprint")}.items() if v}
        whoami = self.shell(serial, "id", timeout=15)
        uid0 = "uid=0(" in whoami.stdout
        p.access_level = "adb shell (pre-existing root - reported, not obtained)" if uid0 else "adb shell (uid shell, no root)"
        p.limitations = list(BASE_LIMITATIONS)
        if props.get("ro.crypto.state") == "encrypted":
            p.limitations.append(f"Storage encryption active ({props.get('ro.crypto.type', 'unknown')}): data is only "
                                 "readable through the running OS on an unlocked device.")
        return p

    def collect(self, serial: str, dest: Path, *, remote_paths: list[str] | None = None,
                content_queries: list[str] | None = None, logcat: bool = True, progress=None) -> Path:
        """Logical collection into ``dest`` (later imported as evidence).

        Produces getprop.txt, packages.txt, optional content_*.txt, logcat.txt,
        pulled shared-storage files and ``acquisition_manifest.json`` listing
        every command, its exit code and timestamp.
        """
        self._check_serial(serial)
        prog = progress or (lambda stage, pct: None)
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=False)
        (dest / "adb").mkdir()
        manifest = {"tool": f"{__app_name__} {__version__}", "adb": self.version(), "serial": serial,
                    "started_at": utcnow().isoformat(), "commands": [], "method": "ADB logical collection (no root)"}

        def run(args, out_file=None, timeout=120):
            r = self.runner(args, timeout=timeout)
            manifest["commands"].append({"args": args, "returncode": r.returncode, "at": utcnow().isoformat(),
                                         "stderr": r.stderr[:500]})
            if out_file is not None and r.returncode == 0:
                out_file.write_text(r.stdout, encoding="utf-8")
            return r

        prog("Device properties", 5)
        run([self.adb, "-s", serial, "shell", "getprop"], dest / "adb" / "getprop.txt")
        prog("Installed packages", 15)
        run([self.adb, "-s", serial, "shell", "pm", "list", "packages", "-f", "-i"], dest / "adb" / "packages.txt")
        for i, name in enumerate(content_queries or []):
            if name not in CONTENT_URIS:
                raise ValidationError(f"Unknown content query '{name}'.")
            prog(f"Content provider {name}", 25 + i * 5)
            r = run([self.adb, "-s", serial, "shell", "content", "query", "--uri", CONTENT_URIS[name]],
                    dest / "adb" / f"content_{name}.txt")
            if r.returncode != 0 or "Permission Denial" in r.stdout + r.stderr:
                manifest.setdefault("limitations", []).append(f"content query {name} refused by the OS (permissions).")
        if logcat:
            prog("Logcat", 45)
            run([self.adb, "-s", serial, "logcat", "-d", "-v", "threadtime"], dest / "adb" / "logcat.txt")
        for i, rp in enumerate(remote_paths or []):
            if not REMOTE_PATH_RE.match(rp) or ".." in rp.split("/"):
                raise ValidationError(f"Remote path not allowed (shared storage only): {rp}")
            prog(f"Pulling {rp}", 50 + int(45 * i / max(1, len(remote_paths))))
            local = dest / "shared_storage"
            local.mkdir(exist_ok=True)
            run([self.adb, "-s", serial, "pull", "-a", rp, str(local)], timeout=3600)
        manifest["finished_at"] = utcnow().isoformat()
        (dest / "acquisition_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        prog("Done", 100)
        return dest
