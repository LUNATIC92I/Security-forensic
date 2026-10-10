"""Common structures for authorised device connectors.

Connectors only use documented, user-authorised channels (USB debugging
authorised on the device, iOS pairing/"Trust this computer", local backups).
They never attempt to bypass a lock screen, exploit a vulnerability, escalate
privileges or disable a security protection. Reported access levels describe
what was *actually* available - a logical collection is never presented as a
physical extraction.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

from ..core.timeutils import utcnow


@dataclass
class DeviceProbe:
    platform: str
    serial: str
    label: str = ""
    manufacturer: str = ""
    model: str = ""
    os_version: str = ""
    identifiers: dict = field(default_factory=dict)
    connection_state: str = "unknown"
    access_level: str = "none"
    limitations: list[str] = field(default_factory=list)
    probed_at: datetime = field(default_factory=utcnow)
    raw: dict = field(default_factory=dict)


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


def default_runner(args: list[str], timeout: int = 60) -> CommandResult:
    """Run an external tool without a shell (no injection), with a timeout."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False,
                           encoding="utf-8", errors="replace")
        return CommandResult(args, p.returncode, p.stdout, p.stderr)
    except FileNotFoundError:
        return CommandResult(args, 127, "", f"{args[0]}: not found")
    except subprocess.TimeoutExpired:
        return CommandResult(args, 124, "", "timeout")


def which(tool: str, env_var: str | None = None) -> str | None:
    import os
    if env_var and os.environ.get(env_var):
        return os.environ[env_var]
    return shutil.which(tool)
