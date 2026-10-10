# Architecture - LUNATIC MOBILE FORENSICS

## Layers

```
            +-----------------------+   +------------------+   +--------------------+
 UI         |  gui/ (PySide6)       |   |  cli.py          |   |  api/ (FastAPI,    |
            |  pages, wizard, lock  |   |  automation      |   |  127.0.0.1 only)   |
            +-----------+-----------+   +--------+---------+   +---------+----------+
                        \______________________ | ___________________/
                                                v
 Services   services/  auth  cases  devices  evidence  analysis  correlation  search
                       findings  reports  backup  audit   (RBAC + case access in base.py)
                 |            |                 |              |              |
 Engines    ingest/      analyzers/        correlation/     reports/     acquisition/
            safety,      android, ios,     engine.py        data, html,  adb, ios
            plugins      messaging, ...    (pure functions) pdf          (subprocess, no shell)
                 \___________|_________________|_____________/
 Storage    storage/  SQLAlchemy models, encrypted column types, migrations, Database
 Core       core/     config, security (argon2, Fernet, scrypt KEK), rbac, time, hashing, normalize
```

* The UI layers never touch the database directly; every read goes through a service that checks the
  session (inactivity lock), the role permission and the case membership.
* Engines are free of database code and unit-tested in isolation.
* Everything runs locally. No component sends evidence to a remote server.

## Data flow of an evidence item

1. `ingest.registry.precheck` - magic-byte type, size, plugin selection, plugin-specific risks.
2. `EvidenceService.import_evidence` - hash source -> copy to `vault/<case>/<EV>/original` -> re-hash ->
   read-only -> plugin extracts *from the vault copy* to `work/` -> per-file inventory (SHA-256, type).
3. `AnalysisService.run` - pre-analysis integrity check (abort on mismatch) -> analyzers matched by
   content -> `Artifact` rows (raw + interpreted, source file/table/row, parser name & version) ->
   application inventory -> post-analysis integrity check -> correlation rebuild.
4. `CorrelationService` - duplicates, shared identifiers, contact links (facts), call/message and
   spatio-temporal proximity (hypotheses), temporal anomalies.
5. `ReportService` - HTML/PDF, hashed and audited.

## Extension points

| Extension | How |
|-----------|-----|
| New container format | subclass `ingest.plugins.base.ImportPlugin`, call `ingest.registry.register_plugin()` |
| New artefact parser / app adapter | subclass `analyzers.base.Analyzer` (content-based `matches`, `parse` yielding `ArtifactRecord`), call `analyzers.register_analyzer()` |
| New correlation rule | pure function in `correlation/engine.py`, add to `CorrelationService.rebuild` |
| PostgreSQL | set `LUNATIC_DATABASE_URL=postgresql+psycopg://...` (`pip install .[postgres]`); migrations are dialect-neutral |
| Schema change | append a function to `storage/migrations.MIGRATIONS` (never edit released ones) |

## Database (main tables)

`users`, `cases`, `case_members`, `devices`, `evidence`, `evidence_files`, `integrity_checks`,
`analysis_jobs`, `artifacts`, `correlations`, `findings`, `reports`, `audit_log`, `schema_version`.
Encrypted at rest (Fernet): `cases.description`, `devices.identifiers`, `artifacts.data`, `findings.text`.
