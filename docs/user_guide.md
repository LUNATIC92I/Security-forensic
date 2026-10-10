# User guide

## 1. First start
1. Install (`scripts/install.sh` or `scripts\install.ps1`), set `LUNATIC_MASTER_PASSPHRASE`, launch
   `scripts/run.sh` / `scripts\run.bat`.
2. The first run asks for the **administrator** account. Then sign in.
3. Administrator: *Users & roles* -> create investigators, analysts, auditors.

| Role | Can do |
|------|--------|
| Administrator | everything, users, backups |
| Investigator | create cases, manage members, import, acquire devices, analyse, findings, reports, audit view |
| Analyst | analyse, search, findings, reports on assigned cases |
| Auditor | case metadata, audit trail, integrity verification - no evidence content |

## 2. Investigation
*Investigations* -> **New investigation**: title, legal authority (warrant, requisition, consent), scope,
description (encrypted), case timezone (used for display and for naive timestamps). Add authorised
investigators. Set the status (open, in progress, suspended, closed, archived - no import once closed).
The case selector at the top applies to all pages.

## 3. Importing evidence
*Evidence & import* -> **Import evidence...** (assistant):
1. choose a file or folder, document the acquisition method, tool and version, link a device;
2. read the **safety inspection** (real type, size, structure, blocking risks, warnings) - rejected
   sources cannot be imported;
3. confirm. The source is hashed, copied read-only into the vault, verified, extracted to a working copy
   and (optionally) analysed. Progress is shown in the status bar.

Supported: ZIP, TAR(.gz/.bz2/.xz), Android adb backups (unencrypted, or AES-256 encrypted when the
backup password is supplied in the wizard's *Backup password* field / CLI `--ask-password` or
`--password-env VAR`), iOS backups folders (unencrypted, iOS 10+), SQLite databases, media, documents,
JSON/CSV/XML exports, logs, raw images (experimental carving). The password is verified before
extraction, used in memory only and never stored or logged (the audit records only that one was
supplied). Encrypted iOS backups are refused with an explanation. No password guessing is performed.

**Verify integrity** re-hashes originals; any mismatch raises an alert on the dashboard and blocks analysis.

## 4. Devices
*Devices* -> **Detect connected devices** lists Android devices (adb) with their state (an unauthorised
device shows that the RSA prompt must be accepted), paired iOS devices and local iOS backups.
**Register selected** records the device with the actually available access level and limitations
(authorisation reference required). **ADB logical collection** gathers properties, packages, optional
content providers, logcat and shared-storage paths, then imports and analyses them. **iOS backup** uses
`idevicebackup2` on a trusted device. No root, jailbreak, exploit or lock bypass is ever attempted.

## 5. Reviewing data
* *Artefacts*: one tab per category; each record shows interpreted values, **original values**, the source
  (file, table, row), parser and version; images get a secure preview. "Add to finding basket" collects
  references for findings. Recovered fragments are flagged *experimental*.
* *Timeline*: normalised timeline, daily histogram (click a bar to zoom), most active periods.
* *Relations*: graph of counterparts per evidence source, sized by volume.
* *Map*: recorded (blue) vs estimated (orange) coordinates, offline; export GeoJSON / KML.
* *Correlations*: observed facts (green), hypotheses (amber), temporal anomalies (red), each with its
  supporting artefacts.
* *Search* (also Ctrl+K): phone in any format, e-mail, name, words (optionally inside full content),
  period, SHA-256 (artefacts and inventoried files), type, conversation, geographic box; paginated and
  traceable to the source.

## 6. Findings and reports
*Findings & reports*: record **facts** (must cite artefacts), **interpretations** and **hypotheses**.
Generate PDF or HTML reports: they are hashed and registered. See `examples/sample_report.pdf`.

## 7. Audit and security
*Audit & custody*: full action history (imports, views, searches, analyses, exports, logins, denials),
**Verify audit chain**, evidence custody status. The session locks after inactivity (or Ctrl+L).
*Users & roles* (admin): encrypted backup of database, keys and vault - restore with
`python -m lunatic_forensics restore <file> <empty_dir>`.

## 8. Command line
```
python -m lunatic_forensics --home DIR init --admin admin
python -m lunatic_forensics --user admin case-create "Title" --authority "REF" --timezone Europe/Paris
python -m lunatic_forensics --user admin precheck SOURCE
python -m lunatic_forensics --user admin import CASE_ID SOURCE --analyze
python -m lunatic_forensics --user admin search CASE_ID --phone "06 39 98 00 01"
python -m lunatic_forensics --user admin verify CASE_ID
python -m lunatic_forensics --user admin report CASE_ID --format pdf
python -m lunatic_forensics demo-data ./synthetic_dataset
python -m lunatic_forensics devices
python -m lunatic_forensics --user admin api        # http://127.0.0.1:8765/docs
```
