"""Application configuration.

Configuration is resolved from (in order) explicit arguments, environment
variables prefixed with ``LUNATIC_`` and defaults. Everything is local by
default: no setting enables any network transmission of evidence.
"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


def _default_home() -> Path:
    env = os.environ.get("LUNATIC_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".lunatic_forensics"


class ImportLimits(BaseModel):
    """Limits protecting the importer against decompression bombs & abuse."""

    max_source_bytes: int = 64 * 1024**3          # 64 GiB per evidence source
    max_total_uncompressed: int = 128 * 1024**3   # 128 GiB extracted per source
    max_member_bytes: int = 32 * 1024**3          # 32 GiB per extracted member
    max_files: int = 500_000
    max_compression_ratio: float = 200.0          # per member
    max_path_depth: int = 64


class AppConfig(BaseModel):
    home: Path = Field(default_factory=_default_home)
    database_url: str | None = None
    session_timeout_minutes: int = 15
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    default_country_code: str = "33"   # used for heuristic phone normalisation
    display_timezone: str = "UTC"
    api_host: str = "127.0.0.1"
    api_port: int = 8765
    limits: ImportLimits = Field(default_factory=ImportLimits)

    @property
    def vault_dir(self) -> Path:
        return self.home / "vault"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def keys_dir(self) -> Path:
        return self.home / "keys"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    @property
    def backups_dir(self) -> Path:
        return self.home / "backups"

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        env = os.environ.get("LUNATIC_DATABASE_URL")
        if env:
            return env
        return f"sqlite:///{(self.home / 'lunatic.db').as_posix()}"

    def ensure_dirs(self) -> None:
        for d in (self.home, self.vault_dir, self.reports_dir, self.keys_dir,
                  self.logs_dir, self.backups_dir):
            d.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:  # pragma: no cover - e.g. some Windows FS
                pass

    @classmethod
    def from_env(cls, **overrides) -> "AppConfig":
        data: dict = {}
        if "LUNATIC_SESSION_TIMEOUT" in os.environ:
            data["session_timeout_minutes"] = int(os.environ["LUNATIC_SESSION_TIMEOUT"])
        if "LUNATIC_COUNTRY_CODE" in os.environ:
            data["default_country_code"] = os.environ["LUNATIC_COUNTRY_CODE"]
        if "LUNATIC_TIMEZONE" in os.environ:
            data["display_timezone"] = os.environ["LUNATIC_TIMEZONE"]
        data.update(overrides)
        return cls(**data)
