"""Security primitives: password hashing, policy, data-at-rest encryption."""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import ForensicError, ValidationError

log = logging.getLogger(__name__)

_hasher = PasswordHasher()

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_policy(password: str) -> None:
    problems = []
    if len(password) < 12:
        problems.append("at least 12 characters")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a symbol")
    if problems:
        raise ValidationError("Password must contain " + ", ".join(problems) + ".")


def validate_username(username: str) -> None:
    if not USERNAME_RE.match(username or ""):
        raise ValidationError("Username must be 3-64 characters: letters, digits, '_', '.', '-'.")


def derive_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    return Scrypt(salt=salt, length=length, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


class KeyManager:
    """Manages the data-encryption key (DEK) used for sensitive DB fields.

    * If ``LUNATIC_MASTER_PASSPHRASE`` (or an explicit passphrase) is supplied,
      the DEK is wrapped with a scrypt-derived key (AES-GCM) - recommended.
    * Otherwise the DEK is stored in a file restricted to the current user and
      a warning is logged. Full-disk encryption is strongly recommended.
    """

    FILE = "master.key"

    def __init__(self, keys_dir: Path, passphrase: str | None = None):
        self.keys_dir = Path(keys_dir)
        self.passphrase = passphrase if passphrase is not None else os.environ.get("LUNATIC_MASTER_PASSPHRASE")

    @property
    def path(self) -> Path:
        return self.keys_dir / self.FILE

    def load_or_create(self) -> bytes:
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            return self._load()
        dek = Fernet.generate_key()
        self._store(dek)
        return dek

    def _store(self, dek: bytes) -> None:
        if self.passphrase:
            salt = secrets.token_bytes(16)
            nonce = secrets.token_bytes(12)
            kek = derive_key(self.passphrase, salt)
            wrapped = AESGCM(kek).encrypt(nonce, dek, b"lunatic-dek")
            doc = {"version": 1, "mode": "wrapped", "kdf": "scrypt",
                   "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
                   "wrapped": base64.b64encode(wrapped).decode()}
        else:
            log.warning("No master passphrase configured: data key stored unwrapped (file permissions only).")
            doc = {"version": 1, "mode": "plain", "key": dek.decode()}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc))
        try:
            os.chmod(tmp, 0o600)
        except OSError:  # pragma: no cover
            pass
        tmp.replace(self.path)

    def _load(self) -> bytes:
        doc = json.loads(self.path.read_text())
        if doc.get("mode") == "plain":
            return doc["key"].encode()
        if not self.passphrase:
            raise ForensicError("The data key is passphrase-protected: set LUNATIC_MASTER_PASSPHRASE.")
        kek = derive_key(self.passphrase, base64.b64decode(doc["salt"]))
        try:
            return AESGCM(kek).decrypt(base64.b64decode(doc["nonce"]), base64.b64decode(doc["wrapped"]), b"lunatic-dek")
        except Exception as exc:  # cryptography raises InvalidTag
            raise ForensicError("Invalid master passphrase.") from exc


class Encryptor:
    """Authenticated symmetric encryption (Fernet: AES-128-CBC + HMAC-SHA256)."""

    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt_bytes(self, token: bytes) -> bytes:
        try:
            return self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise ForensicError("Encrypted value could not be decrypted (wrong key or tampered data).") from exc

    def encrypt_text(self, text: str) -> str:
        return self.encrypt_bytes(text.encode("utf-8")).decode("ascii")

    def decrypt_text(self, token: str) -> str:
        return self.decrypt_bytes(token.encode("ascii")).decode("utf-8")

    def encrypt_json(self, obj) -> str:
        return self.encrypt_text(json.dumps(obj, default=str, ensure_ascii=False))

    def decrypt_json(self, token: str):
        return json.loads(self.decrypt_text(token))


def new_token() -> str:
    return secrets.token_urlsafe(32)
