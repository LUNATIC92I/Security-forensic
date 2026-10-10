"""Import plugin interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ...core.config import ImportLimits


@dataclass
class ExtractedFile:
    rel_path: str            # path inside the working directory
    virtual_path: str = ""   # logical path on the device (e.g. iOS domain path)


@dataclass
class ExtractionResult:
    container_type: str
    files: list[ExtractedFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    device_info: dict = field(default_factory=dict)


@dataclass
class PrecheckResult:
    blocking: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    structure: dict = field(default_factory=dict)


class ImportPlugin(ABC):
    name: str = "base"
    description: str = ""
    container_type: str = "file"

    @abstractmethod
    def probe(self, src: Path, detected: str) -> bool:
        """Return True if this plugin handles the source."""

    def precheck(self, src: Path, detected: str, limits: ImportLimits, password: str | None = None) -> PrecheckResult:
        return PrecheckResult()

    @abstractmethod
    def extract(self, src: Path, workdir: Path, limits: ImportLimits, password: str | None = None) -> ExtractionResult:
        """Produce working copies of the source content inside ``workdir``."""
