"""LUNATIC MOBILE FORENSICS - local-first mobile forensics platform.

The package is organised in layers:

* ``core``         configuration, security primitives, RBAC, time handling
* ``storage``      SQLAlchemy models, database bootstrap, schema migrations
* ``ingest``       safe evidence import (container plugins, archive safety)
* ``analyzers``    per-artifact parsing engines (contacts, messages, ...)
* ``correlation``  timeline, duplicates, inconsistencies, relationship graph
* ``services``     business services used by the GUI, CLI and API
* ``acquisition``  authorised device connectors (ADB, libimobiledevice)
* ``reports``      HTML / PDF report generation
* ``api``          optional local FastAPI server (127.0.0.1 only)
* ``gui``          PySide6 desktop application
"""

__app_name__ = "LUNATIC MOBILE FORENSICS"
__version__ = "0.1.0"
