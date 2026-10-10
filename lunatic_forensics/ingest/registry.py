"""Import plugin registry and pre-import inspection."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.config import ImportLimits
from .plugins.android_backup import AndroidBackupPlugin
from .plugins.archives import DirectoryPlugin, SingleFilePlugin, TarPlugin, ZipPlugin
from .plugins.base import ImportPlugin
from .plugins.ios_backup import IosBackupPlugin
from .safety import EXECUTABLE_TYPES, detect_type, extension_mismatch

_PLUGINS: list[ImportPlugin] = [
    IosBackupPlugin(), AndroidBackupPlugin(), ZipPlugin(), TarPlugin(), DirectoryPlugin(), SingleFilePlugin(),
]


def register_plugin(plugin: ImportPlugin, first: bool = True) -> None:
    """Register an additional container plugin (extension point)."""
    if first:
        _PLUGINS.insert(0, plugin)
    else:
        _PLUGINS.insert(len(_PLUGINS) - 1, plugin)


def plugins() -> list[ImportPlugin]:
    return list(_PLUGINS)


def select_plugin(src: Path, detected: str) -> ImportPlugin | None:
    for p in _PLUGINS:
        if p.probe(src, detected):
            return p
    return None


@dataclass
class PrecheckReport:
    source: str
    detected_type: str
    size: int
    plugin: str | None
    accepted: bool
    blocking: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    structure: dict = field(default_factory=dict)


def precheck(src: Path, limits: ImportLimits) -> PrecheckReport:
    src = Path(src)
    if src.is_symlink():
        return PrecheckReport(str(src), "symlink", 0, None, False, ["Symbolic links are not accepted as sources."])
    if not src.exists():
        return PrecheckReport(str(src), "missing", 0, None, False, ["Source does not exist."])
    detected = detect_type(src)
    size = src.stat().st_size if src.is_file() else 0
    report = PrecheckReport(str(src), detected, size, None, True)
    if src.is_file():
        if size > limits.max_source_bytes:
            report.blocking.append(f"File exceeds the maximum accepted size ({limits.max_source_bytes} bytes).")
        if size == 0:
            report.warnings.append("Empty file.")
        if extension_mismatch(src, detected):
            report.warnings.append(f"Extension '{src.suffix}' does not match detected content '{detected}'.")
        if detected in EXECUTABLE_TYPES:
            report.warnings.append(f"Executable content detected ({detected}): it will be stored isolated "
                                   "and never executed.")
    plugin = select_plugin(src, detected)
    if plugin is None:
        report.blocking.append("No import plugin accepts this source.")
    else:
        report.plugin = plugin.name
        pre = plugin.precheck(src, detected, limits)
        report.blocking += pre.blocking
        report.warnings += pre.warnings
        report.structure = pre.structure
    report.accepted = not report.blocking
    return report
