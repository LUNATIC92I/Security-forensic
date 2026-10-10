"""Database bootstrap: engine, sessions, SQLite hardening, migrations."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import timezone
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from . import models
from .migrations import migrate


def _attach_utc(session, instance):
    """Re-attach UTC tzinfo to datetimes loaded from SQLite (stored naive)."""
    for col in instance.__table__.columns:
        if isinstance(col.type, models.TZDateTime):
            v = instance.__dict__.get(col.key)
            if v is not None and v.tzinfo is None:
                instance.__dict__[col.key] = v.replace(tzinfo=timezone.utc)


class Database:
    def __init__(self, url: str, echo: bool = False):
        self.url = url
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine: Engine = create_engine(url, echo=echo, future=True, connect_args=connect_args)
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", self._sqlite_pragmas)
        self._factory = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)
        event.listen(self._factory, "loaded_as_persistent", _attach_utc)

    @staticmethod
    def _sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA secure_delete=ON")
        cur.close()

    def init(self) -> int:
        return migrate(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._factory()
        try:
            yield s
            s.commit()
        except Exception as exc:
            if getattr(exc, "commit_session", False):
                s.commit()
            else:
                s.rollback()
            raise
        finally:
            s.close()

    def dispose(self) -> None:
        self.engine.dispose()
