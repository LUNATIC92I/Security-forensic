"""ZIP / TAR / generic file and directory import plugins."""
from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from ...core.config import ImportLimits
from ...core.hashing import iter_regular_files
from ..safety import is_tar, safe_extract_tar, safe_extract_zip, zip_risks
from .base import ExtractedFile, ExtractionResult, ImportPlugin, PrecheckResult



class ZipPlugin(ImportPlugin):
    name = "zip"
    description = "ZIP archives (safe extraction). Office/APK files are kept as single documents."
    container_type = "zip"

    def probe(self, src, detected):
        if detected != "zip" or src.is_dir():
            return False
        if src.suffix.lower() in (".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".apk", ".ipa", ".jar"):
            return False
        return True

    def precheck(self, src, detected, limits, password: str | None = None):
        blocking, warnings = zip_risks(src, limits)
        with_count = {}
        try:
            with zipfile.ZipFile(src) as zf:
                infos = zf.infolist()
                with_count = {"entries": len(infos), "declared_uncompressed": sum(i.file_size for i in infos)}
        except zipfile.BadZipFile:
            pass
        return PrecheckResult(blocking, warnings, with_count)

    def extract(self, src, workdir, limits, password: str | None = None):
        stats = safe_extract_zip(src, workdir, limits)
        return ExtractionResult(self.container_type, [ExtractedFile(f, f) for f in stats.files], stats.warnings)


class TarPlugin(ImportPlugin):
    name = "tar"
    description = "TAR archives, optionally gzip/bzip2/xz compressed (safe extraction)."
    container_type = "tar"

    def probe(self, src, detected):
        return not src.is_dir() and detected in ("tar", "gzip", "bzip2", "xz") and is_tar(src)

    def precheck(self, src, detected, limits, password: str | None = None):
        return PrecheckResult(structure={"compression": detected})

    def extract(self, src, workdir, limits, password: str | None = None):
        stats = safe_extract_tar(src, workdir, limits)
        return ExtractionResult(self.container_type, [ExtractedFile(f, f) for f in stats.files], stats.warnings)


class DirectoryPlugin(ImportPlugin):
    name = "directory"
    description = "Folder of exported files (symlinks are never followed)."
    container_type = "directory"

    def probe(self, src, detected):
        return detected == "directory"

    def precheck(self, src, detected, limits, password: str | None = None):
        res = PrecheckResult()
        n = 0
        total = 0
        for p in src.rglob("*"):
            if p.is_symlink():
                res.warnings.append(f"Symbolic link skipped: {p.relative_to(src)}")
                continue
            if p.is_file():
                n += 1
                total += p.stat().st_size
        if n > limits.max_files:
            res.blocking.append(f"Too many files ({n}).")
        if total > limits.max_source_bytes:
            res.blocking.append("Directory exceeds size limit.")
        res.structure = {"files": n, "bytes": total}
        return res

    def extract(self, src, workdir, limits, password: str | None = None):
        files = []
        for p in iter_regular_files(src):
            rel = p.relative_to(src)
            target = workdir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
            files.append(ExtractedFile(rel.as_posix(), rel.as_posix()))
        return ExtractionResult(self.container_type, files)


class SingleFilePlugin(ImportPlugin):
    name = "file"
    description = "Single evidence file (database, media, document, export, log...)."
    container_type = "file"

    def probe(self, src, detected):
        return src.is_file()

    def extract(self, src, workdir, limits, password: str | None = None):
        workdir.mkdir(parents=True, exist_ok=True)
        target = workdir / src.name
        shutil.copy2(src, target)
        return ExtractionResult(self.container_type, [ExtractedFile(src.name, src.name)])
