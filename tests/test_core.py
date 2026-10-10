from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from lunatic_forensics.core import timeutils as T
from lunatic_forensics.core.errors import ForensicError, PermissionDenied, ValidationError
from lunatic_forensics.core.normalize import (normalize_email, normalize_identifier, normalize_phone, pack_identifiers,
                                              unpack_identifiers)
from lunatic_forensics.core.rbac import Perm, Role, has_perm, require
from lunatic_forensics.core.security import (Encryptor, KeyManager, hash_password, validate_password_policy,
                                             validate_username, verify_password)

UTC = timezone.utc


class TestTime:
    def test_unix_units(self):
        ref = datetime(2026, 3, 14, 8, 0, tzinfo=UTC)
        s = int(ref.timestamp())
        assert T.auto_unix(s) == (ref, "unix_s")
        assert T.auto_unix(s * 1000) == (ref, "unix_ms")
        assert T.auto_unix(s * 1_000_000) == (ref, "unix_us")
        assert T.auto_unix(s * 1_000_000_000)[1] == "unix_ns"
        assert T.auto_unix(None) == (None, None)
        assert T.auto_unix("abc") == (None, None)

    def test_mac_absolute_seconds_and_nanoseconds(self):
        ref = datetime(2026, 3, 14, 8, 0, tzinfo=UTC)
        secs = ref.timestamp() - 978307200
        assert T.from_mac_absolute(secs) == (ref, "mac_absolute_s")
        dt, method = T.from_mac_absolute(int(secs * 1e9))
        assert method == "mac_absolute_ns" and abs((dt - ref).total_seconds()) < 1e-3

    def test_webkit(self):
        assert T.from_webkit_micros(11644473600 * 1_000_000) == datetime(1970, 1, 1, tzinfo=UTC)

    def test_parse_naive_uses_default_timezone(self):
        dt, method = T.parse_datetime("2026-03-14 10:00:00", "Europe/Paris")
        assert dt == datetime(2026, 3, 14, 9, 0, tzinfo=UTC)
        assert method == "naive_assumed_Europe/Paris"
        dt, method = T.parse_datetime("2026-07-14T10:00:00", "Europe/Paris")  # DST
        assert dt == datetime(2026, 7, 14, 8, 0, tzinfo=UTC)

    def test_parse_aware_and_exif_format(self):
        assert T.parse_datetime("2026-03-14T10:00:00+02:00")[0] == datetime(2026, 3, 14, 8, 0, tzinfo=UTC)
        assert T.parse_datetime("2026-03-14T08:00:00Z")[0] == datetime(2026, 3, 14, 8, 0, tzinfo=UTC)
        assert T.parse_datetime("2026:03:14 08:00:00", "UTC")[0] == datetime(2026, 3, 14, 8, 0, tzinfo=UTC)
        assert T.parse_datetime("not a date") == (None, None)

    def test_overflow_is_none(self):
        assert T.from_unix_seconds(1e20) is None

    def test_display_and_plausibility(self):
        dt = datetime(2026, 3, 14, 8, 0, tzinfo=UTC)
        assert T.to_display(dt, "Europe/Paris").startswith("2026-03-14 09:00:00")
        assert T.is_plausible(dt, datetime(2026, 10, 1, tzinfo=UTC))
        assert not T.is_plausible(datetime(1990, 1, 1, tzinfo=UTC))


class TestNormalize:
    @pytest.mark.parametrize("raw,expected", [
        ("06 39 98 00 01", "+33639980001"), ("+33 6 39 98 00 01", "+33639980001"),
        ("0033639980001", "+33639980001"), ("(+33) 639-980-001", "+33639980001"), ("3630", "3630"),
        ("", None), (None, None), ("alice@example.org", None), ("12", None), ("Bob", None)])
    def test_phone(self, raw, expected):
        assert normalize_phone(raw, "33") == expected

    def test_email_and_identifiers(self):
        assert normalize_email("MAILTO:Bob.Durand@Example.ORG ") == "bob.durand@example.org"
        assert normalize_email("not-an-email") is None
        assert normalize_identifier("33639980001@s.whatsapp.net") == "+33639980001"
        assert normalize_identifier("120363@g.us") == "120363@g.us"
        assert normalize_identifier("Dan@Example.org") == "dan@example.org"

    def test_pack_roundtrip(self):
        packed = pack_identifiers(["+33639980001", "a@example.org", None, "+33639980001"])
        assert packed == "|+33639980001|a@example.org|"
        assert unpack_identifiers(packed) == ["+33639980001", "a@example.org"]
        assert pack_identifiers([]) == ""


class TestRbac:
    def test_matrix(self):
        assert has_perm(Role.ADMIN, Perm.MANAGE_USERS)
        assert not has_perm(Role.INVESTIGATOR, Perm.MANAGE_USERS)
        assert has_perm(Role.INVESTIGATOR, Perm.IMPORT_EVIDENCE)
        assert not has_perm(Role.ANALYST, Perm.IMPORT_EVIDENCE)
        assert has_perm(Role.ANALYST, Perm.RUN_ANALYSIS)
        assert not has_perm(Role.AUDITOR, Perm.VIEW_ARTIFACTS)
        assert has_perm(Role.AUDITOR, Perm.VIEW_AUDIT)
        with pytest.raises(PermissionDenied):
            require("analyst", Perm.CREATE_CASE)


class TestSecurity:
    def test_password_hash(self):
        h = hash_password("S3cure!Password")
        assert h.startswith("$argon2")
        assert verify_password(h, "S3cure!Password")
        assert not verify_password(h, "wrong")
        assert not verify_password("garbage", "x")

    @pytest.mark.parametrize("pw", ["short1!A", "alllowercase123!", "ALLUPPER123!!", "NoDigitsHere!!", "NoSymbols1234"])
    def test_password_policy_rejects(self, pw):
        with pytest.raises(ValidationError):
            validate_password_policy(pw)

    def test_username(self):
        validate_username("j.doe-01")
        with pytest.raises(ValidationError):
            validate_username("bad name;")

    def test_encryptor_roundtrip_and_tamper(self):
        from cryptography.fernet import Fernet
        e = Encryptor(Fernet.generate_key())
        tok = e.encrypt_json({"body": "secret message", "n": 1})
        assert "secret" not in tok
        assert e.decrypt_json(tok) == {"body": "secret message", "n": 1}
        bad = tok[:-5] + ("A" if tok[-5] != "A" else "B") + tok[-4:]
        with pytest.raises(ForensicError):
            e.decrypt_text(bad)
        with pytest.raises(ForensicError):
            Encryptor(Fernet.generate_key()).decrypt_text(tok)

    def test_key_manager_wrapped(self, tmp_path):
        km = KeyManager(tmp_path / "k", passphrase="Correct horse 1!")
        key = km.load_or_create()
        assert "wrapped" in (tmp_path / "k" / "master.key").read_text()
        assert KeyManager(tmp_path / "k", passphrase="Correct horse 1!").load_or_create() == key
        with pytest.raises(ForensicError):
            KeyManager(tmp_path / "k", passphrase="wrong").load_or_create()
        with pytest.raises(ForensicError):
            KeyManager(tmp_path / "k", passphrase="").load_or_create()

    def test_key_manager_plain(self, tmp_path):
        km = KeyManager(tmp_path / "k2", passphrase="")
        key = km.load_or_create()
        assert KeyManager(tmp_path / "k2", passphrase="").load_or_create() == key
