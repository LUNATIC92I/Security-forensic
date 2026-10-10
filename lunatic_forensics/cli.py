"""Command line interface (headless operations, automation, validation).

Authentication: ``--user`` plus password from the ``LUNATIC_PASSWORD``
environment variable or an interactive prompt (never a command-line argument).
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from . import __app_name__, __version__
from .core.config import AppConfig
from .core.errors import ForensicError, ImportRejected


def _ctx(args):
    from .services.context import AppContext
    cfg = AppConfig.from_env(**({"home": Path(args.home)} if args.home else {}))
    return AppContext(cfg)


def _login(ctx, args):
    user = args.user or os.environ.get("LUNATIC_USER")
    if not user:
        sys.exit("--user is required")
    pwd = os.environ.get("LUNATIC_PASSWORD") or getpass.getpass(f"Password for {user}: ")
    return ctx.auth.authenticate(user, pwd)


def _progress(stage, pct):
    print(f"  [{pct:3d}%] {stage}", file=sys.stderr)


def cmd_init(args):
    ctx = _ctx(args)
    if ctx.auth.has_users():
        print("Already initialised.")
        return
    user = args.admin or input("Administrator username: ")
    pwd = os.environ.get("LUNATIC_PASSWORD") or getpass.getpass("Administrator password: ")
    ctx.auth.bootstrap_admin(user, pwd, args.full_name or "Administrator")
    print(f"Initialised {ctx.config.home} (schema v{ctx.schema_version}); administrator '{user}' created.")


def cmd_user_add(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    pwd = os.environ.get("LUNATIC_NEW_PASSWORD") or getpass.getpass(f"Password for new user {args.username}: ")
    uid = ctx.auth.create_user(a, args.username, pwd, args.role, args.full_name or "")
    print(f"User {args.username} created (id {uid}, role {args.role}).")


def cmd_case_create(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    cid = ctx.cases.create(a, args.title, args.description or "", args.authority or "", args.scope or "", args.timezone)
    print(json.dumps({"id": cid, "uid": ctx.cases.get(a, cid).uid}))


def cmd_case_list(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    for c in ctx.cases.dashboard(a):
        print(f"{c.id:4d} {c.uid}  {c.status:12s} ev={c.evidence:<3d} art={c.artifacts:<6d} alerts={c.integrity_alerts}  {c.title}")


def _container_password(args):
    """Backup password from an environment variable or an interactive prompt (never argv)."""
    if getattr(args, "password_env", None):
        pw = os.environ.get(args.password_env)
        if not pw:
            sys.exit(f"environment variable {args.password_env} is empty")
        return pw
    if getattr(args, "ask_password", False):
        return getpass.getpass("Backup password: ")
    return None


def cmd_precheck(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    r = ctx.evidence.precheck(a, args.path, password=_container_password(args))
    from dataclasses import asdict
    print(json.dumps(asdict(r), indent=2, default=str))
    return 0 if r.accepted else 2


def cmd_import(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    try:
        ev = ctx.evidence.import_evidence(a, args.case, args.path, acquisition_method=args.method,
                                          tool_name=args.tool or "", tool_version=args.tool_version or "",
                                          notes=args.notes or "", progress=_progress,
                                          container_password=_container_password(args))
    except ImportRejected as exc:
        print(f"REJECTED: {exc}", *[f"  - {r}" for r in exc.risks], sep="\n", file=sys.stderr)
        return 2
    e = ctx.evidence.get(a, ev)
    print(json.dumps({"evidence_id": ev, "uid": e.uid, "sha256": e.sha256, "files": e.file_count}))
    if args.analyze:
        job = ctx.analysis.run(a, ev, progress=_progress)
        j = ctx.analysis.job(a, job)
        print(json.dumps({"job": job, "status": j.status, "artifacts": j.artifact_count, "errors": j.errors[:20]}))


def cmd_analyze(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    job = ctx.analysis.run(a, args.evidence, only=args.only or None, progress=_progress)
    j = ctx.analysis.job(a, job)
    print(json.dumps({"job": job, "status": j.status, "artifacts": j.artifact_count, "by_analyzer": j.analyzers,
                      "errors": j.errors[:50]}, indent=2))


def cmd_search(args):
    from .services.search_service import SearchQuery
    ctx = _ctx(args)
    a = _login(ctx, args)
    q = SearchQuery(text=args.text, deep=args.deep, phone=args.phone, email=args.email, name=args.name,
                    sha256=args.sha256, categories=args.category or [], page=args.page, page_size=args.page_size,
                    start=datetime.fromisoformat(args.start) if args.start else None,
                    end=datetime.fromisoformat(args.end) if args.end else None)
    res = ctx.search.search(a, args.case, q)
    print(f"{res.total} result(s), page {res.page}/{res.pages}")
    for h in res.hits:
        print(f"#{h.artifact_id:<6} {h.timestamp.isoformat() if h.timestamp else '-':32s} {h.category:10s} {h.summary[:90]}"
              f"\n        source: {h.evidence_uid}:{h.source_path} [{h.source_table}#{h.source_rowid}] ({h.parser})")
    for f in res.file_hits:
        print(f"FILE {f['evidence']}:{f['path']} sha256={f['sha256']}")


def cmd_verify(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    checks = ctx.evidence.verify_case(a, args.case, "manual-cli")
    bad = [c for c in checks if not c.ok]
    for c in checks:
        print(f"{'OK   ' if c.ok else 'ALERT'} evidence#{c.evidence_id} expected={c.expected} observed={c.observed}")
    ok, broken, n = ctx.audit.verify_chain()
    print(f"Audit chain: {'intact' if ok else f'BROKEN at entry {broken}'} ({n} entries)")
    return 1 if bad or not ok else 0


def cmd_report(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    out = ctx.reports.generate(a, args.case, args.format, Path(args.output) if args.output else None)
    print(out)


def cmd_finding(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    fid = ctx.findings.add(a, args.case, args.kind, args.title, args.text or "", args.artifacts or [])
    print(f"Finding {fid} recorded.")


def cmd_devices(args):
    from .acquisition.adb import AdbConnector
    from .acquisition.ios import IosConnector, find_local_backups
    adb = AdbConnector()
    print("Android (adb):", "available" if adb.available() else "adb not found")
    for serial, state, attrs in adb.list_devices():
        p = adb.probe(serial, state, attrs)
        print(f"  {serial} state={state} {p.label} {p.os_version} access={p.access_level}")
        for l in p.limitations:
            print(f"     - {l}")
    ios = IosConnector()
    print("iOS (libimobiledevice):", "available" if ios.available() else "tools not found")
    for udid in ios.list_devices():
        p = ios.probe(udid)
        print(f"  {udid} {p.label} {p.os_version} access={p.access_level}")
    for b in find_local_backups():
        print(f"  local backup: {b['path']} {b.get('device_name', '')} iOS {b.get('os_version', '')} "
              f"encrypted={b.get('is_encrypted')}")


def cmd_demo_data(args):
    from .synthetic import build_demo_dataset
    out = build_demo_dataset(Path(args.dest))
    for k, v in out.items():
        print(f"{k:16s} {v}")


def cmd_backup(args):
    ctx = _ctx(args)
    a = _login(ctx, args)
    pw = os.environ.get("LUNATIC_BACKUP_PASSPHRASE") or getpass.getpass("Backup passphrase: ")
    print(ctx.backup.create(a, pw, Path(args.dest) if args.dest else None))


def cmd_restore(args):
    from .services.backup_service import BackupService
    pw = os.environ.get("LUNATIC_BACKUP_PASSPHRASE") or getpass.getpass("Backup passphrase: ")
    files = BackupService.restore(Path(args.file), pw, Path(args.target), AppConfig().limits)
    print(f"Restored {len(files)} files into {args.target}. Start with LUNATIC_HOME={args.target}")


def cmd_api(args):
    from .api.server import run
    run(_ctx(args), host=args.host, port=args.port)


def cmd_gui(args):
    from .gui.app import main
    if args.home:
        os.environ["LUNATIC_HOME"] = args.home
    main()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lunatic-forensics", description=f"{__app_name__} {__version__}")
    p.add_argument("--home", help="data directory (default: $LUNATIC_HOME or ~/.lunatic_forensics)")
    p.add_argument("--user", help="username for authenticated commands")
    p.add_argument("--version", action="version", version=f"{__app_name__} {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="initialise data directory and create the first administrator")
    s.add_argument("--admin")
    s.add_argument("--full-name")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("user-add", help="create a user (admin)")
    s.add_argument("username")
    s.add_argument("--role", required=True, choices=["admin", "investigator", "analyst", "auditor"])
    s.add_argument("--full-name")
    s.set_defaults(fn=cmd_user_add)

    s = sub.add_parser("case-create")
    s.add_argument("title")
    s.add_argument("--description")
    s.add_argument("--authority", help="legal authority / mandate reference")
    s.add_argument("--scope")
    s.add_argument("--timezone", default="UTC")
    s.set_defaults(fn=cmd_case_create)

    s = sub.add_parser("case-list")
    s.set_defaults(fn=cmd_case_list)

    s = sub.add_parser("precheck", help="inspect a source without importing it")
    s.add_argument("path")
    s.add_argument("--password-env", help="env variable holding the backup password (encrypted .ab)")
    s.add_argument("--ask-password", action="store_true", help="prompt for the backup password")
    s.set_defaults(fn=cmd_precheck)

    s = sub.add_parser("import", help="import an evidence source into a case")
    s.add_argument("case", type=int)
    s.add_argument("path")
    s.add_argument("--method", default="file import")
    s.add_argument("--tool")
    s.add_argument("--tool-version")
    s.add_argument("--notes")
    s.add_argument("--analyze", action="store_true")
    s.add_argument("--password-env", help="env variable holding the backup password (encrypted .ab)")
    s.add_argument("--ask-password", action="store_true", help="prompt for the backup password")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("analyze")
    s.add_argument("evidence", type=int)
    s.add_argument("--only", nargs="*")
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("search")
    s.add_argument("case", type=int)
    s.add_argument("--text")
    s.add_argument("--deep", action="store_true")
    s.add_argument("--phone")
    s.add_argument("--email")
    s.add_argument("--name")
    s.add_argument("--sha256")
    s.add_argument("--category", nargs="*")
    s.add_argument("--start")
    s.add_argument("--end")
    s.add_argument("--page", type=int, default=1)
    s.add_argument("--page-size", type=int, default=50)
    s.set_defaults(fn=cmd_search)

    s = sub.add_parser("verify", help="verify evidence hashes and audit chain")
    s.add_argument("case", type=int)
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("finding")
    s.add_argument("case", type=int)
    s.add_argument("--kind", required=True, choices=["fact", "interpretation", "hypothesis"])
    s.add_argument("--title", required=True)
    s.add_argument("--text")
    s.add_argument("--artifacts", nargs="*", type=int)
    s.set_defaults(fn=cmd_finding)

    s = sub.add_parser("report")
    s.add_argument("case", type=int)
    s.add_argument("--format", choices=["pdf", "html"], default="pdf")
    s.add_argument("--output")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("devices", help="detect connected devices and local iOS backups")
    s.set_defaults(fn=cmd_devices)

    s = sub.add_parser("demo-data", help="generate the synthetic test dataset")
    s.add_argument("dest")
    s.set_defaults(fn=cmd_demo_data)

    s = sub.add_parser("backup", help="encrypted backup of database, keys and vault")
    s.add_argument("--dest")
    s.set_defaults(fn=cmd_backup)

    s = sub.add_parser("restore", help="restore an encrypted backup into an empty directory")
    s.add_argument("file")
    s.add_argument("target")
    s.set_defaults(fn=cmd_restore)

    s = sub.add_parser("api", help="run the local REST API (loopback only)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.set_defaults(fn=cmd_api)

    s = sub.add_parser("gui", help="start the desktop application")
    s.set_defaults(fn=cmd_gui)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args) or 0
    except ForensicError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
