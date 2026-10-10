"""Timestamp decoding and normalisation.

Every decoder returns the UTC datetime *and* the name of the conversion that
was applied, so reports can document how a raw value was interpreted.
All datetimes stored by the application are timezone-aware UTC.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

UTC = timezone.utc
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
MAC_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)       # Apple Cocoa / Core Data
WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)    # Chromium / Windows FILETIME

# Plausibility window for mobile artefacts
PLAUSIBLE_MIN = datetime(2000, 1, 1, tzinfo=UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


def _safe_add(epoch: datetime, **kw) -> datetime | None:
    try:
        return epoch + timedelta(**kw)
    except (OverflowError, ValueError):
        return None


def from_unix_seconds(v: float) -> datetime | None:
    return _safe_add(UNIX_EPOCH, seconds=float(v))


def from_unix_millis(v: float) -> datetime | None:
    return _safe_add(UNIX_EPOCH, milliseconds=float(v))


def from_unix_micros(v: float) -> datetime | None:
    return _safe_add(UNIX_EPOCH, microseconds=float(v))


def from_webkit_micros(v: float) -> datetime | None:
    return _safe_add(WEBKIT_EPOCH, microseconds=float(v))


def from_mac_absolute(v: float) -> tuple[datetime | None, str]:
    """Apple absolute time; newer iOS databases store nanoseconds."""
    v = float(v)
    if abs(v) > 1e14:
        return _safe_add(MAC_EPOCH, microseconds=v / 1000.0), "mac_absolute_ns"
    return _safe_add(MAC_EPOCH, seconds=v), "mac_absolute_s"


def auto_unix(v) -> tuple[datetime | None, str | None]:
    """Decode a Unix timestamp whose unit is unknown, based on magnitude."""
    if v is None or v == "":
        return None, None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None, None
    a = abs(f)
    if a == 0:
        return None, None
    if a < 1e11:
        return from_unix_seconds(f), "unix_s"
    if a < 1e14:
        return from_unix_millis(f), "unix_ms"
    if a < 1e17:
        return from_unix_micros(f), "unix_us"
    return _safe_add(UNIX_EPOCH, microseconds=f / 1000.0), "unix_ns"


def parse_datetime(value, default_tz: str = "UTC") -> tuple[datetime | None, str | None]:
    """Parse ISO-8601 strings or numeric epochs into aware UTC datetimes.

    Naive datetimes are assumed to be in ``default_tz`` and the method name
    records that assumption.
    """
    if value is None:
        return None, None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=ZoneInfo(default_tz)).astimezone(UTC), f"naive_assumed_{default_tz}"
        return value.astimezone(UTC), "aware"
    if isinstance(value, (int, float)):
        return auto_unix(value)
    s = str(value).strip()
    if not s:
        return None, None
    if s.lstrip("-").replace(".", "", 1).isdigit():
        return auto_unix(s)
    s2 = s.replace("Z", "+00:00") if s.endswith("Z") else s
    for fmt in (None, "%Y:%m:%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                "%Y%m%dT%H%M%S", "%Y%m%d"):
        try:
            dt = datetime.fromisoformat(s2) if fmt is None else datetime.strptime(s, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            return dt.replace(tzinfo=ZoneInfo(default_tz)).astimezone(UTC), f"naive_assumed_{default_tz}"
        return dt.astimezone(UTC), "iso8601"
    return None, None


def ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def to_iso(dt: datetime | None) -> str | None:
    dt = ensure_utc(dt)
    return dt.isoformat() if dt else None


def to_display(dt: datetime | None, tz: str = "UTC") -> str:
    dt = ensure_utc(dt)
    if dt is None:
        return ""
    local = dt.astimezone(ZoneInfo(tz))
    return local.strftime("%Y-%m-%d %H:%M:%S %Z")


def is_plausible(dt: datetime | None, reference: datetime | None = None) -> bool:
    dt = ensure_utc(dt)
    if dt is None:
        return False
    ref = ensure_utc(reference) or utcnow()
    return PLAUSIBLE_MIN <= dt <= ref + timedelta(days=1)
