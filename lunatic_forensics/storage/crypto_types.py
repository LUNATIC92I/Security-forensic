"""SQLAlchemy column types transparently encrypting values at rest."""
from __future__ import annotations

from sqlalchemy.types import Text, TypeDecorator

from ..core.errors import ForensicError
from ..core.security import Encryptor

_encryptor: Encryptor | None = None


def set_encryptor(enc: Encryptor | None) -> None:
    global _encryptor
    _encryptor = enc


def get_encryptor() -> Encryptor:
    if _encryptor is None:
        raise ForensicError("Encryption key not initialised.")
    return _encryptor


class EncryptedText(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return get_encryptor().encrypt_text(str(value))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return get_encryptor().decrypt_text(value)


class EncryptedJSON(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return get_encryptor().encrypt_json(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return get_encryptor().decrypt_json(value)
