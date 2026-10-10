# Technical documentation

## Security model

| Control | Implementation |
|---------|----------------|
| Authentication | argon2id hashes (`argon2-cffi`), password policy (12+ chars, 4 classes), lockout after 5 failures for 15 min, constant-ish time for unknown users |
| Sessions | in-memory `AuthSession`; locked after `session_timeout_minutes` of inactivity (service-side check + GUI idle timer); unlock requires the password |
| Authorisation | `core/rbac.py` role -> permission matrix; case membership enforced in `ServiceBase.case_for` (inaccessible cases are reported as *not found*) |
| Encryption at rest | Fernet data key; wrapped with an scrypt-derived AES-GCM key when `LUNATIC_MASTER_PASSPHRASE` is set (recommended), otherwise file stored with 0600 permissions and a warning. Indexed metadata (timestamps, categories, normalised identifiers, short summaries) stays in clear for search: use full-disk encryption (BitLocker/LUKS/FileVault) |
| SQL injection | SQLAlchemy expressions with bound parameters only; LIKE wildcards escaped; tested with injection strings |
| Hostile files | magic-byte detection, extension mismatch & executable warnings, zip/tar traversal rejection, links skipped, decompression-bomb limits with streamed byte counting, XML DTD/entity refusal, Pillow decompression-bomb guard, Qt image allocation limit for previews, SQLite opened `mode=ro&immutable=1` on working copies |
| Isolation | originals read-only in the vault; extracted content is never executed; subprocesses (adb, libimobiledevice) are run with argument lists, no shell, validated serials and paths |
| Audit | append-only hash chain (`audit_log.entry_hash = SHA256(prev_hash + canonical entry)`); security events committed even when the action fails (`core.errors.persist`) |
| Errors | user-facing messages never include evidence content or secrets; tracebacks go to the technical log only |
| Backups | `.lmfbak`: tar.gz stream encrypted with AES-256-GCM in 4 MiB frames, AAD binds frame index and final flag (reordering/truncation detected), scrypt key from passphrase; restore only into an empty directory |
| Network | no outbound connection; optional API refuses non-loopback binding unless `LUNATIC_API_ALLOW_REMOTE=1` |

## Configuration (environment)

| Variable | Meaning |
|----------|---------|
| `LUNATIC_HOME` | data directory (default `~/.lunatic_forensics`) |
| `LUNATIC_MASTER_PASSPHRASE` | wraps the data-encryption key (strongly recommended) |
| `LUNATIC_DATABASE_URL` | SQLAlchemy URL (default SQLite in `LUNATIC_HOME`) |
| `LUNATIC_SESSION_TIMEOUT` | inactivity lock, minutes (default 15) |
| `LUNATIC_COUNTRY_CODE` | default country code for phone normalisation (default 33) |
| `LUNATIC_ADB` | path to `adb` |
| `LUNATIC_USER` / `LUNATIC_PASSWORD` | CLI automation (avoid on shared machines) |

Data directory: `lunatic.db`, `keys/master.key`, `vault/<case>/<evidence>/{original,work,derived}`,
`reports/`, `logs/lunatic.log` (rotating), `backups/`, `staging/` (device collections before import).

## Timestamp decoding

Every artefact stores `timestamp_raw`, `timestamp_method` and the UTC value. Methods: `unix_s|ms|us|ns`
(magnitude heuristic), `mac_absolute_s|ns` (2001 epoch), `webkit_us` (1601 epoch), `mp4_mvhd_1904_epoch`,
`exif_with_offset` / `exif_local_time_assumed_<tz>`, `ical_*`, `logcat_year_assumed_<year>_tz_<tz>`,
`naive_assumed_<tz>` (case timezone), `iso8601`.

## Parsers (analyzers)

Run `python -m lunatic_forensics` then see `AnalysisService.analyzers_catalog()`; summary:

| Analyzer | Source (documented schema) | Status |
|----------|---------------------------|--------|
| android.sms | mmssms.db `sms`, `pdu/part/addr` (MMS text) | stable |
| android.contacts | contacts2.db `raw_contacts/data/mimetypes` | stable |
| android.calllog | calllog.db / contacts2.db `calls` | stable |
| android.calendar | calendar.db `Events` | stable |
| android.adb_getprop / adb_packages | ADB connector outputs | stable |
| android.adb_content_query | `content query` outputs (ambiguous separators flagged) | partial |
| ios.sms | sms.db (`text` + heuristic `attributedBody` decoding) | stable |
| ios.addressbook / callhistory / calendar | AddressBook.sqlitedb, CallHistory.storedata, Calendar.sqlitedb | stable |
| ios.notes | NoteStore.sqlite (protobuf text only, locked notes not decrypted), legacy notes.sqlite | partial |
| ios.photos_db | Photos.sqlite `ZASSET` GPS | stable |
| messaging.whatsapp_android | decrypted msgstore.db, legacy and current schemas | partial |
| messaging.whatsapp_ios | ChatStorage.sqlite | partial |
| export.sms_backup_restore_xml | SMS Backup & Restore XML | stable |
| browser.* | Chromium History/Cookies(metadata)/Bookmarks, Safari History.db, Firefox places.sqlite | stable |
| media.metadata | JPEG/PNG/GIF/WEBP/BMP EXIF+GPS, MP4/MOV mvhd + ISO 6709; HEIC hash only | stable |
| documents.metadata | OOXML, ODF (metadata + text), PDF Info dictionary (no text extraction) | stable / partial (PDF) |
| documents.text_index | fallback text indexing | stable |
| export.vcard / icalendar / gpx | RFC 6350 / RFC 5545 / GPX 1.1 | stable |
| export.google_location_history | Takeout Records.json, Timeline rawSignals/timelinePath | partial |
| export.lunatic_exchange | own documented format (docs/exchange_format.md) | stable |
| logs.system | logcat threadtime, syslog, ISO-8601 lines | stable |
| recovery.sqlite_residual | free-list pages, unallocated areas, freeblocks, WAL frames | experimental |
| recovery.file_carving | JPEG/PNG/PDF header-footer carving in raw images | experimental |
| apps.inventory | package detection from paths, adapter support status | stable |

## Testing

`python -m pytest` (139 tests, ~40 s) - `python -m pytest --cov` for coverage (≈91 % excluding GUI).
GUI tests run offscreen (`QT_QPA_PLATFORM=offscreen`) and are skipped automatically if Qt cannot load.
`tests/test_end_to_end.py` is the non-regression snapshot of parser outputs on the synthetic scenario.
