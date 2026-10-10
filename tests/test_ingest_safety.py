"""Security tests: malformed files, hostile archives, real type detection."""
import zipfile

import pytest

from lunatic_forensics import synthetic as S
from lunatic_forensics.core.config import ImportLimits
from lunatic_forensics.core.errors import ImportRejected
from lunatic_forensics.ingest.registry import precheck
from lunatic_forensics.ingest.safety import detect_type, safe_extract_tar, safe_extract_zip, sanitize_member_path


@pytest.fixture
def limits():
    return ImportLimits(max_compression_ratio=100)


def test_detect_types(tmp_path):
    assert detect_type(S.android_calllog(tmp_path / "a.db")) == "sqlite"
    assert detect_type(S.jpeg_with_gps(tmp_path / "a.jpg")) == "jpeg"
    assert detect_type(S.png_plain(tmp_path / "a.png")) == "png"
    assert detect_type(S.pdf(tmp_path / "a.pdf")) == "pdf"
    assert detect_type(S.docx(tmp_path / "a.docx")) == "zip"
    assert detect_type(S.mp4_with_location(tmp_path / "a.mp4")) == "mp4"
    assert detect_type(S.android_backup(tmp_path / "a.ab")) == "android_backup"
    assert detect_type(S.vcard(tmp_path / "a.vcf")) == "vcard"
    assert detect_type(S.gpx(tmp_path / "a.gpx")) == "xml"
    assert detect_type(S.exchange_json(tmp_path / "a.json")) == "json"
    assert detect_type(S.adb_getprop(tmp_path / "getprop.txt")) == "text"
    assert detect_type(S.tar_with_symlink(tmp_path / "a.tar")) == "tar"
    (tmp_path / "e").write_bytes(b"")
    assert detect_type(tmp_path / "e") == "empty"
    (tmp_path / "x.exe").write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    assert detect_type(tmp_path / "x.exe") == "pe_executable"
    assert detect_type(tmp_path) == "directory"


@pytest.mark.parametrize("name", ["../a", "/etc/passwd", "C:/Windows/x", "a/../../b", "a\\..\\..\\b", "a\x00b"])
def test_sanitize_rejects(name, limits):
    with pytest.raises(ImportRejected):
        sanitize_member_path(name, limits)


def test_sanitize_cleans(limits):
    assert str(sanitize_member_path("./dir//sub/file:name?.txt", limits)) == "dir/sub/file_name_.txt"


def test_zip_traversal_rejected(tmp_path, limits):
    z = S.zip_traversal(tmp_path / "t.zip")
    rep = precheck(z, limits)
    assert not rep.accepted and any("traversal" in b.lower() for b in rep.blocking)
    with pytest.raises(ImportRejected):
        safe_extract_zip(z, tmp_path / "out", limits)
    assert not (tmp_path / "evil.txt").exists()


def test_zip_bomb_rejected(tmp_path, limits):
    z = S.zip_bomb(tmp_path / "b.zip", size_mb=20)
    rep = precheck(z, limits)
    assert not rep.accepted and any("ratio" in b for b in rep.blocking)


def test_zip_real_size_enforced_even_if_header_lies(tmp_path):
    z = tmp_path / "lie.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("f.bin", b"A" * 5000)
    lim = ImportLimits(max_total_uncompressed=1000)
    with pytest.raises(ImportRejected):
        safe_extract_zip(z, tmp_path / "o", lim)


def test_zip_too_many_files(tmp_path):
    z = tmp_path / "many.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for i in range(30):
            zf.writestr(f"f{i}.txt", "x")
    rep = precheck(z, ImportLimits(max_files=10))
    assert not rep.accepted


def test_corrupted_zip(tmp_path, limits):
    p = tmp_path / "bad.zip"
    p.write_bytes(b"PK\x03\x04" + b"garbage" * 20)
    assert not precheck(p, limits).accepted


def test_tar_symlink_skipped(tmp_path, limits):
    t = S.tar_with_symlink(tmp_path / "s.tar")
    stats = safe_extract_tar(t, tmp_path / "out", limits)
    assert stats.files == ["regular.txt"]
    assert any("Link skipped" in w for w in stats.warnings)
    assert not (tmp_path / "out" / "link_to_passwd").exists()


def test_tar_traversal_rejected(tmp_path, limits):
    with pytest.raises(ImportRejected):
        safe_extract_tar(S.tar_traversal(tmp_path / "t.tar"), tmp_path / "out", limits)
    assert not (tmp_path / "outside.txt").exists()


def test_encrypted_android_backup_rejected(tmp_path, limits):
    rep = precheck(S.android_backup(tmp_path / "e.ab", encrypted=True), limits)
    assert not rep.accepted and any("Encrypted Android backup" in b for b in rep.blocking)


def test_uncompressed_android_backup_accepted(tmp_path, limits):
    rep = precheck(S.android_backup(tmp_path / "u.ab", compressed=False), limits)
    assert rep.accepted and rep.plugin == "android_backup"


def test_encrypted_ios_backup_rejected(tmp_path, limits):
    rep = precheck(S.ios_backup(tmp_path / "ios", encrypted=True), limits)
    assert not rep.accepted and any("Encrypted iOS backup" in b for b in rep.blocking)


def test_legacy_ios_backup_rejected(tmp_path, limits):
    d = tmp_path / "legacy"
    d.mkdir()
    (d / "Manifest.mbdb").write_bytes(b"mbdb\x05\x00")
    rep = precheck(d, limits)
    assert not rep.accepted and "Manifest.mbdb" in rep.blocking[0]


def test_warnings_mismatch_executable_size(tmp_path):
    p = tmp_path / "photo.jpg"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    rep = precheck(p, ImportLimits())
    assert rep.accepted
    assert any("does not match" in w for w in rep.warnings)
    assert any("never executed" in w for w in rep.warnings)
    rep = precheck(p, ImportLimits(max_source_bytes=10))
    assert not rep.accepted


def test_missing_and_symlink_sources(tmp_path, limits):
    assert not precheck(tmp_path / "nope", limits).accepted
    target = tmp_path / "t.txt"
    target.write_text("x")
    link = tmp_path / "l.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks not supported")
    assert not precheck(link, limits).accepted
