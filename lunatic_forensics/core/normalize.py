"""Identifier normalisation (phone numbers, e-mails, messaging IDs).

Phone normalisation is *heuristic* (no carrier numbering plan database):
``00`` prefixes become ``+``, national numbers starting with ``0`` get the
configured default country code. The raw value is always preserved next to
the normalised one so analysts can check the interpretation.
"""
from __future__ import annotations

import re

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_NON_DIGIT = re.compile(r"\D")


def normalize_phone(raw, default_cc: str = "33") -> str | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or "@" in s:
        return None
    if re.search(r"[A-Za-z]", s.replace("ext", "").replace("x", "")):
        return None
    keep = re.sub(r"[^\d+]", "", s)
    if not keep:
        return None
    if keep.startswith("+"):
        d = "+" + _NON_DIGIT.sub("", keep[1:])
    elif keep.startswith("00"):
        d = "+" + keep[2:]
    elif keep.startswith("0") and default_cc and len(keep) >= 9:
        d = "+" + default_cc + keep[1:]
    else:
        d = _NON_DIGIT.sub("", keep)
    digits = _NON_DIGIT.sub("", d)
    if len(digits) < 3 or len(digits) > 17:
        return None
    return d


def normalize_email(raw) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if s.startswith("mailto:"):
        s = s[7:]
    return s if EMAIL_RE.match(s) else None


def normalize_identifier(raw, default_cc: str = "33") -> str | None:
    """Normalise phone numbers, e-mails and messaging handles (e.g. WhatsApp JIDs)."""
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    if s.endswith("@s.whatsapp.net") or s.endswith("@c.us"):
        num = s.split("@", 1)[0]
        return "+" + num if num.isdigit() else s.lower()
    if s.endswith("@g.us") or s.endswith("@broadcast") or s.endswith("@lid"):
        return s.lower()
    email = normalize_email(s)
    if email:
        return email
    phone = normalize_phone(s, default_cc)
    if phone:
        return phone
    return s.lower()[:200]


def pack_identifiers(ids) -> str:
    """Encode identifiers as ``|a|b|`` to allow exact LIKE '%|a|%' matching."""
    clean = sorted({i for i in ids if i})
    return "|" + "|".join(clean) + "|" if clean else ""


def unpack_identifiers(packed: str) -> list[str]:
    return [p for p in (packed or "").split("|") if p]
