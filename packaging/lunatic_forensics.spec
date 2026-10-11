# PyInstaller spec - one-file, windowed executable.
#   pyinstaller --noconfirm packaging/lunatic_forensics.spec
# Produces dist/LunaticMobileForensics(.exe). With no argument it opens the GUI;
# with arguments it behaves as the CLI (e.g. "LunaticMobileForensics.exe self-test --output r.txt").
# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

HERE = Path(SPECPATH)
ROOT = HERE.parent
hidden = (collect_submodules("lunatic_forensics") + collect_submodules("argon2")
          + ["_cffi_backend", "sqlalchemy.dialects.sqlite", "tzdata"])
datas = collect_data_files("tzdata") + collect_data_files("reportlab")

a = Analysis([str(HERE / "launcher.py")], pathex=[str(ROOT)], hiddenimports=hidden, datas=datas,
             excludes=["tkinter", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
                       "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.QtQuick3D", "PySide6.QtMultimedia",
                       "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtPdf", "PySide6.QtQml",
                       "PySide6.QtQuick", "PySide6.QtDesigner", "fastapi", "uvicorn", "pytest", "IPython"],
             noarchive=False)
pyz = PYZ(a.pure)
is_win = sys.platform == "win32"
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="LunaticMobileForensics",
          console=False, upx=False, strip=False, runtime_tmpdir=None,
          icon=str(HERE / "lunatic.ico") if is_win else None,
          version=str(HERE / "version_info.txt") if is_win else None)
