"""Domain exceptions.

Messages carried by these exceptions are meant to be shown to users: they
must never include secrets, key material or evidence content.
"""


class ForensicError(Exception):
    """Base class for all application errors."""


class AuthenticationError(ForensicError):
    """Invalid credentials, disabled or locked account."""


class PermissionDenied(ForensicError):
    """The current user lacks the permission or case membership required."""


class SessionLocked(ForensicError):
    """The session is locked or expired and must be re-authenticated."""


class ValidationError(ForensicError):
    """User supplied data failed validation."""


class NotFound(ForensicError):
    """Requested object does not exist (or is not visible to the user)."""


class ImportRejected(ForensicError):
    """An evidence source failed the pre-import safety checks."""

    def __init__(self, message: str, risks: list[str] | None = None):
        super().__init__(message)
        self.risks = risks or []


class IntegrityViolation(ForensicError):
    """A hash verification detected a modification of evidence."""


class UnsupportedFormat(ForensicError):
    """The format is recognised but no tested parser exists for it."""


def persist(exc: Exception) -> Exception:
    """Mark an exception so the surrounding DB session COMMITS before propagating.

    Used when security/custody records written in the same transaction (audit
    entries, failed integrity checks) must survive the error being raised.
    """
    exc.commit_session = True
    return exc
