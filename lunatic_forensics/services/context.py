"""Application context wiring configuration, storage and services together."""
from __future__ import annotations

import logging
import logging.handlers

from ..core.config import AppConfig
from ..core.security import Encryptor, KeyManager
from ..storage.crypto_types import set_encryptor
from ..storage.database import Database
from .analysis_service import AnalysisService
from .audit_service import AuditService
from .auth_service import AuthService
from .backup_service import BackupService
from .case_service import CaseService
from .correlation_service import CorrelationService
from .device_service import DeviceService
from .evidence_service import EvidenceService
from .finding_service import FindingService
from .report_service import ReportService
from .search_service import SearchService


def configure_logging(config: AppConfig, level=logging.INFO) -> None:
    """Attach a rotating file handler for this data directory (replacing one for another directory)."""
    root = logging.getLogger("lunatic")
    root.setLevel(level)
    target = str((config.logs_dir / "lunatic.log").resolve())
    for h in list(root.handlers):
        if getattr(h, "_lunatic", False):
            if h.baseFilename == target:
                return
            root.removeHandler(h)
            h.close()
    fh = logging.handlers.RotatingFileHandler(target, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    fh._lunatic = True
    root.addHandler(fh)


class AppContext:
    def __init__(self, config: AppConfig | None = None, passphrase: str | None = None):
        self.config = config or AppConfig.from_env()
        self.config.ensure_dirs()
        configure_logging(self.config)
        key = KeyManager(self.config.keys_dir, passphrase).load_or_create()
        self.encryptor = Encryptor(key)
        set_encryptor(self.encryptor)
        self.db = Database(self.config.resolved_database_url)
        self.schema_version = self.db.init()
        self.audit = AuditService(self)
        self.auth = AuthService(self)
        self.cases = CaseService(self)
        self.devices = DeviceService(self)
        self.evidence = EvidenceService(self)
        self.analysis = AnalysisService(self)
        self.correlation = CorrelationService(self)
        self.search = SearchService(self)
        self.findings = FindingService(self)
        self.reports = ReportService(self)
        self.backup = BackupService(self)
        self.audit.log("app.start", details={"schema_version": self.schema_version})

    def close(self) -> None:
        self.db.dispose()
