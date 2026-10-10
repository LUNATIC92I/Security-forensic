# PyInstaller spec - build with: pyinstaller --noconfirm packaging/lunatic_forensics.spec
# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hidden = collect_submodules("lunatic_forensics") + ["argon2", "tzdata", "sqlalchemy.dialects.sqlite"]

a = Analysis(["launcher.py"], pathex=[".."], hiddenimports=hidden,
             excludes=["PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.Qt3DCore", "tkinter"],
             noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="LunaticMobileForensics", console=False, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="LunaticMobileForensics")
