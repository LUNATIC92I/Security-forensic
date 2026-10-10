"""ORM models.

Sensitive free text (case descriptions, device identifiers, artefact payloads,
finding text) is encrypted at rest. Indexable metadata (timestamps,
categories, normalised identifiers, short summaries) is stored in clear to
allow searching; deploy on an encrypted volume for full protection.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String,
                        Text, UniqueConstraint)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ..core.timeutils import utcnow
from .crypto_types import EncryptedJSON, EncryptedText


class Base(DeclarativeBase):
    pass


class TZDateTime(DateTime):
    """Timezone-aware datetime (SQLite stores naive values -> we re-attach UTC)."""

    cache_ok = True

    def __init__(self):
        super().__init__(timezone=True)


def _dt():
    return mapped_column(TZDateTime(), default=utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    created_at: Mapped[datetime] = _dt()
    last_login: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    legal_authority: Mapped[str] = mapped_column(String(300), default="")
    scope: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="open")
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = _dt()
    updated_at: Mapped[datetime] = _dt()

    owner: Mapped[User] = relationship()
    members: Mapped[list["CaseMember"]] = relationship(back_populates="case", cascade="all, delete-orphan")
    devices: Mapped[list["Device"]] = relationship(back_populates="case", cascade="all, delete-orphan")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="case", cascade="all, delete-orphan")


class CaseMember(Base):
    __tablename__ = "case_members"
    __table_args__ = (UniqueConstraint("case_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    added_at: Mapped[datetime] = _dt()
    case: Mapped[Case] = relationship(back_populates="members")
    user: Mapped[User] = relationship()


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    label: Mapped[str] = mapped_column(String(200), default="")
    platform: Mapped[str] = mapped_column(String(20), default="unknown")
    manufacturer: Mapped[str] = mapped_column(String(100), default="")
    model: Mapped[str] = mapped_column(String(100), default="")
    os_version: Mapped[str] = mapped_column(String(100), default="")
    identifiers: Mapped[dict | None] = mapped_column(EncryptedJSON, nullable=True)
    access_level: Mapped[str] = mapped_column(String(50), default="none")
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    connection_state: Mapped[str] = mapped_column(String(50), default="not connected")
    authorization_ref: Mapped[str] = mapped_column(String(300), default="")
    collection_scope: Mapped[str] = mapped_column(Text, default="")
    acquired_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    created_at: Mapped[datetime] = _dt()
    case: Mapped[Case] = relationship(back_populates="devices")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    original_name: Mapped[str] = mapped_column(String(500))
    source_path: Mapped[str] = mapped_column(Text)
    stored_path: Mapped[str] = mapped_column(Text)
    working_path: Mapped[str] = mapped_column(Text)
    is_directory: Mapped[bool] = mapped_column(Boolean, default=False)
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    md5: Mapped[str] = mapped_column(String(32), default="")
    detected_type: Mapped[str] = mapped_column(String(50), default="")
    container_type: Mapped[str] = mapped_column(String(50), default="")
    acquisition_method: Mapped[str] = mapped_column(String(200), default="import")
    tool_name: Mapped[str] = mapped_column(String(100), default="")
    tool_version: Mapped[str] = mapped_column(String(50), default="")
    status: Mapped[str] = mapped_column(String(30), default="imported")
    notes: Mapped[str] = mapped_column(Text, default="")
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    imported_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    imported_at: Mapped[datetime] = _dt()

    case: Mapped[Case] = relationship(back_populates="evidence")
    device: Mapped[Device | None] = relationship()
    importer: Mapped[User] = relationship()
    files: Mapped[list["EvidenceFile"]] = relationship(back_populates="evidence", cascade="all, delete-orphan")
    checks: Mapped[list["IntegrityCheck"]] = relationship(back_populates="evidence", cascade="all, delete-orphan")


class EvidenceFile(Base):
    __tablename__ = "evidence_files"
    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    rel_path: Mapped[str] = mapped_column(Text)
    virtual_path: Mapped[str] = mapped_column(Text, default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    detected_type: Mapped[str] = mapped_column(String(50), default="")
    mtime: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    evidence: Mapped[Evidence] = relationship(back_populates="files")


class IntegrityCheck(Base):
    __tablename__ = "integrity_checks"
    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    checked_at: Mapped[datetime] = _dt()
    checked_by: Mapped[str] = mapped_column(String(64))
    context: Mapped[str] = mapped_column(String(100))
    expected: Mapped[str] = mapped_column(String(64))
    observed: Mapped[str] = mapped_column(String(64))
    ok: Mapped[bool] = mapped_column(Boolean)
    details: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[Evidence] = relationship(back_populates="checks")


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"))
    started_by: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = _dt()
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    analyzers: Mapped[dict] = mapped_column(JSON, default=dict)
    artifact_count: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSON, default=list)


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        Index("ix_art_case_cat", "case_id", "category"),
        Index("ix_art_case_ts", "case_id", "timestamp_utc"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    evidence_file_id: Mapped[int | None] = mapped_column(ForeignKey("evidence_files.id"), nullable=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("analysis_jobs.id"), nullable=True)
    category: Mapped[str] = mapped_column(String(30))
    subtype: Mapped[str] = mapped_column(String(60), default="")
    timestamp_utc: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    timestamp_raw: Mapped[str | None] = mapped_column(String(100), nullable=True)
    timestamp_method: Mapped[str | None] = mapped_column(String(60), nullable=True)
    summary: Mapped[str] = mapped_column(String(500), default="")
    identifiers: Mapped[str] = mapped_column(Text, default="")   # "|id1|id2|" for LIKE search
    names: Mapped[str] = mapped_column(Text, default="")
    conversation_id: Mapped[str | None] = mapped_column(String(300), nullable=True, index=True)
    direction: Mapped[str | None] = mapped_column(String(20), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    location_kind: Mapped[str | None] = mapped_column(String(20), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mime: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source_path: Mapped[str] = mapped_column(Text, default="")
    source_table: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source_rowid: Mapped[str | None] = mapped_column(String(50), nullable=True)
    parser_name: Mapped[str] = mapped_column(String(80))
    parser_version: Mapped[str] = mapped_column(String(20))
    is_recovered: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    data: Mapped[dict | None] = mapped_column(EncryptedJSON, nullable=True)  # {"raw":..., "interpreted":...}
    created_at: Mapped[datetime] = _dt()


class Correlation(Base):
    __tablename__ = "correlations"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))          # observed_fact | hypothesis
    rule: Mapped[str] = mapped_column(String(60))
    description: Mapped[str] = mapped_column(Text)
    artifact_ids: Mapped[list] = mapped_column(JSON, default=list)
    score: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = _dt()


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(20))          # fact | interpretation | hypothesis
    title: Mapped[str] = mapped_column(String(300))
    text: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    artifact_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = _dt()


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    generated_by: Mapped[str] = mapped_column(String(64))
    generated_at: Mapped[datetime] = _dt()
    format: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))


class AuditEntry(Base):
    """Hash-chained, append-only audit trail (tamper evident)."""

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = _dt()
    username: Mapped[str] = mapped_column(String(64), default="system")
    action: Mapped[str] = mapped_column(String(80), index=True)
    case_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    object_type: Mapped[str] = mapped_column(String(40), default="")
    object_id: Mapped[str] = mapped_column(String(80), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
