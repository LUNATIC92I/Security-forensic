"""GUI entry point."""
from __future__ import annotations

import sys


def main() -> int:
    from PySide6.QtWidgets import QApplication, QMessageBox

    from .. import __app_name__
    from ..core.config import AppConfig
    from ..core.errors import ForensicError
    from ..services.context import AppContext
    from . import theme
    from .login import BootstrapDialog, LoginDialog
    from .main_window import MainWindow

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(__app_name__)
    theme.apply(app)
    try:
        ctx = AppContext(AppConfig.from_env())
    except ForensicError as exc:
        QMessageBox.critical(None, __app_name__, str(exc))
        return 1
    if not ctx.auth.has_users():
        if BootstrapDialog(ctx).exec() != BootstrapDialog.Accepted:
            return 0
    dlg = LoginDialog(ctx)
    if dlg.exec() != LoginDialog.Accepted:
        return 0
    win = MainWindow(ctx, dlg.session)
    win.show()
    code = app.exec()
    ctx.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
