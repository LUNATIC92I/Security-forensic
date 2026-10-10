"""Images and videos: hashes, EXIF, GPS and container metadata.

Image decoding uses Pillow with its decompression-bomb guard enabled;
images are never rendered by this analyzer. HEIC metadata requires an
optional decoder (pillow-heif) - without it only hashes are reported.
"""
from __future__ import annotations

import re
import struct
from datetime import datetime, timedelta, timezone

from PIL import Image, UnidentifiedImageError

from ..core.timeutils import parse_datetime
from .base import Analyzer, ArtifactRecord, Category

Image.MAX_IMAGE_PIXELS = 200_000_000

IMAGE_TYPES = {"jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif", "webp": "image/webp",
               "bmp": "image/bmp", "heic": "image/heic"}
VIDEO_TYPES = {"mp4": "video/mp4", "mov": "video/quicktime", "avi": "video/x-msvideo"}
AUDIO_TYPES = {"mp3": "audio/mpeg", "wav": "audio/wav", "ogg": "audio/ogg"}

EXIF_IFD, GPS_IFD = 0x8769, 0x8825
MP4_EPOCH = datetime(1904, 1, 1, tzinfo=timezone.utc)


def _rat(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError, ZeroDivisionError):
        try:
            return v[0] / v[1]
        except Exception:
            return float("nan")


def gps_to_decimal(dms, ref) -> float | None:
    try:
        d, m, s = (_rat(x) for x in dms)
        val = d + m / 60 + s / 3600
        if ref in ("S", "W", b"S", b"W"):
            val = -val
        if val != val:  # NaN
            return None
        return round(val, 7)
    except Exception:
        return None


def _clean(v):
    if isinstance(v, bytes):
        return v[:64].hex()
    if isinstance(v, tuple):
        return [_clean(x) for x in v]
    try:
        float(v) if not isinstance(v, (str, int)) else None
    except (TypeError, ValueError):
        return str(v)
    return v if isinstance(v, (str, int, float)) else str(v)


def read_exif(path) -> dict:
    out: dict = {}
    with Image.open(path) as img:
        out["width"], out["height"] = img.size
        out["format"] = img.format
        exif = img.getexif()
        if not exif:
            return out
        base = {int(k): _clean(v) for k, v in exif.items()}
        ifd = {int(k): _clean(v) for k, v in exif.get_ifd(EXIF_IFD).items()}
        gps_raw = exif.get_ifd(GPS_IFD)
        out["make"] = base.get(271)
        out["model"] = base.get(272)
        out["software"] = base.get(305)
        out["datetime"] = base.get(306)
        out["datetime_original"] = ifd.get(36867)
        out["datetime_digitized"] = ifd.get(36868)
        out["offset_time_original"] = ifd.get(36881)
        if gps_raw:
            lat = gps_to_decimal(gps_raw.get(2), gps_raw.get(1)) if gps_raw.get(2) else None
            lon = gps_to_decimal(gps_raw.get(4), gps_raw.get(3)) if gps_raw.get(4) else None
            out["gps"] = {"latitude": lat, "longitude": lon,
                          "altitude": _rat(gps_raw[6]) if 6 in gps_raw else None,
                          "gps_date": gps_raw.get(29), "raw": {int(k): _clean(v) for k, v in gps_raw.items()}}
        out["exif_tags"] = {**{f"0th:{k}": v for k, v in base.items() if k not in (EXIF_IFD, GPS_IFD)},
                            **{f"exif:{k}": v for k, v in ifd.items() if k != 37500}}  # skip MakerNote
    return out


def _iter_boxes(f, start, end):
    pos = start
    while pos + 8 <= end:
        f.seek(pos)
        hdr = f.read(8)
        if len(hdr) < 8:
            return
        size, typ = struct.unpack(">I4s", hdr)
        hlen = 8
        if size == 1:
            size = struct.unpack(">Q", f.read(8))[0]
            hlen = 16
        elif size == 0:
            size = end - pos
        if size < hlen:
            return
        yield typ, pos + hlen, pos + size
        pos += size


ISO6709 = re.compile(rb"([+-]\d{1,2}\.\d{2,})([+-]\d{1,3}\.\d{2,})")


def read_mp4(path, file_size: int) -> dict:
    out: dict = {}
    with open(path, "rb") as f:
        for typ, s, e in _iter_boxes(f, 0, file_size):
            if typ != b"moov":
                continue
            for t2, s2, e2 in _iter_boxes(f, s, e):
                if t2 == b"mvhd":
                    f.seek(s2)
                    ver = f.read(1)[0]
                    f.read(3)
                    if ver == 1:
                        ctime, mtime, scale, dur = struct.unpack(">QQIQ", f.read(28))
                    else:
                        ctime, mtime, scale, dur = struct.unpack(">IIII", f.read(16))
                    out["creation_time_raw"] = ctime
                    out["creation_time"] = (MP4_EPOCH + timedelta(seconds=ctime)).isoformat() if ctime else None
                    out["modification_time"] = (MP4_EPOCH + timedelta(seconds=mtime)).isoformat() if mtime else None
                    out["duration_s"] = round(dur / scale, 3) if scale else None
            if e - s <= 16 * 1024 * 1024:
                f.seek(s)
                blob = f.read(e - s)
                m = ISO6709.search(blob)
                if m and (b"\xa9xyz" in blob or b"ISO6709" in blob):
                    out["gps"] = {"latitude": float(m.group(1)), "longitude": float(m.group(2)),
                                  "source": "QuickTime ISO 6709 location metadata"}
            break
    return out


class MediaAnalyzer(Analyzer):
    name = "media.metadata"
    version = "1.0"
    categories = (Category.MEDIA,)
    description = "Image/video/audio files: SHA-256, EXIF (camera, dates, GPS), MP4/QuickTime metadata."
    sources = "JPEG, PNG, GIF, WEBP, BMP, HEIC (hash only), MP4/MOV, AVI/MP3/WAV/OGG (hash only)"

    def matches(self, f):
        return f.detected_type in IMAGE_TYPES or f.detected_type in VIDEO_TYPES or f.detected_type in AUDIO_TYPES

    def parse(self, f):
        t = f.detected_type
        mime = IMAGE_TYPES.get(t) or VIDEO_TYPES.get(t) or AUDIO_TYPES.get(t)
        meta: dict = {}
        notes = []
        ts = ts_raw = method = None
        lat = lon = None
        try:
            if t in IMAGE_TYPES and t != "heic":
                meta = read_exif(f.path)
                dto = meta.get("datetime_original") or meta.get("datetime")
                if dto:
                    tz = f.default_tz
                    off = meta.get("offset_time_original")
                    if off and re.match(r"^[+-]\d{2}:\d{2}$", str(off)):
                        ts, method = parse_datetime(f"{str(dto).replace(':', '-', 2).replace(' ', 'T')}{off}")
                        method = "exif_with_offset"
                    else:
                        ts, method = parse_datetime(str(dto), tz)
                        method = f"exif_local_time_assumed_{tz}"
                    ts_raw = str(dto)
                gps = meta.get("gps") or {}
                lat, lon = gps.get("latitude"), gps.get("longitude")
            elif t == "heic":
                notes.append("HEIC metadata decoding requires the optional 'pillow-heif' package; hash only.")
            elif t in ("mp4", "mov"):
                meta = read_mp4(f.path, f.size)
                if meta.get("creation_time_raw"):
                    ts, method = parse_datetime(meta["creation_time"])
                    ts_raw, method = str(meta["creation_time_raw"]), "mp4_mvhd_1904_epoch"
                    notes.append("MP4 creation time is UTC per ISO/IEC 14496-12 but some devices write local time.")
                gps = meta.get("gps") or {}
                lat, lon = gps.get("latitude"), gps.get("longitude")
            else:
                notes.append("Container metadata not parsed for this format; hash only.")
        except (UnidentifiedImageError, OSError, struct.error, ValueError, Image.DecompressionBombError) as exc:
            notes.append(f"Metadata could not be read: {type(exc).__name__}")
        if lat is not None and lon is not None and (abs(lat) > 90 or abs(lon) > 180 or (lat == 0 and lon == 0)):
            notes.append("GPS values out of range or null island; ignored.")
            lat = lon = None
        exif_tags = meta.pop("exif_tags", {})
        yield ArtifactRecord(
            category=Category.MEDIA, subtype=t, timestamp=ts, timestamp_raw=ts_raw, timestamp_method=method,
            summary=f"{t.upper()} {f.name}" + (f" {meta.get('make') or ''} {meta.get('model') or ''}".rstrip() if meta.get("make") else "")
                    + (f" @ {lat:.5f},{lon:.5f}" if lat is not None else ""),
            sha256=f.sha256, mime=mime, latitude=lat, longitude=lon,
            location_kind="recorded" if lat is not None else None,
            raw={"exif_tags": exif_tags, "file_size": f.size},
            interpreted={**meta, "file_name": f.name, "path": f.logical_path, "notes": notes,
                         "file_mtime": f.mtime.isoformat() if f.mtime else None})


ANALYZERS = [MediaAnalyzer()]
