"""Optional local REST API (FastAPI).

Security posture: binds to the loopback interface only (non-loopback hosts are
refused), bearer-token authentication backed by the same RBAC/session logic as
the GUI, read-oriented endpoints, no evidence upload or outbound traffic.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime

from pydantic import BaseModel

from ..core.errors import AuthenticationError, ForensicError, NotFound, PermissionDenied, SessionLocked, ValidationError


class Login(BaseModel):
    username: str
    password: str


def create_app(ctx):
    from fastapi import Depends, FastAPI, HTTPException, Query
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from ..services.search_service import SearchQuery

    app = FastAPI(title="LUNATIC MOBILE FORENSICS local API", version="0.1.0", docs_url="/docs", redoc_url=None)
    bearer = HTTPBearer(auto_error=False)

    def actor(cred: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if cred is None:
            raise HTTPException(401, "Missing bearer token")
        try:
            return ctx.auth.session_for_token(cred.credentials)
        except SessionLocked as exc:
            raise HTTPException(401, str(exc))

    def guard(fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except (PermissionDenied,) as exc:
            raise HTTPException(403, str(exc))
        except NotFound as exc:
            raise HTTPException(404, str(exc))
        except (ValidationError, ValueError) as exc:
            raise HTTPException(422, str(exc))
        except SessionLocked as exc:
            raise HTTPException(401, str(exc))
        except ForensicError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/health")
    def health():
        return {"status": "ok", "schema_version": ctx.schema_version}

    @app.post("/auth/login")
    def login(body: Login):
        try:
            s = ctx.auth.authenticate(body.username, body.password)
        except AuthenticationError as exc:
            raise HTTPException(401, str(exc))
        return {"token": s.token, "role": s.role, "expires_after_inactivity_minutes": ctx.config.session_timeout_minutes}

    @app.post("/auth/logout")
    def logout(a=Depends(actor)):
        ctx.auth.logout(a)
        return {"status": "logged out"}

    @app.get("/cases")
    def cases(a=Depends(actor)):
        return [{"id": c.id, "uid": c.uid, "title": c.title, "status": c.status, "evidence": c.evidence,
                 "artifacts": c.artifacts, "integrity_alerts": c.integrity_alerts,
                 "updated_at": c.updated_at.isoformat()} for c in guard(ctx.cases.dashboard, a)]

    @app.get("/cases/{case_id}/evidence")
    def evidence(case_id: int, a=Depends(actor)):
        return [{"id": e.id, "uid": e.uid, "name": e.original_name, "sha256": e.sha256, "size": e.size,
                 "status": e.status, "files": e.file_count} for e in guard(ctx.evidence.list, a, case_id)]

    @app.get("/cases/{case_id}/search")
    def search(case_id: int, a=Depends(actor), text: str | None = None, phone: str | None = None,
               email: str | None = None, sha256: str | None = None, category: list[str] = Query(default=[]),
               start: datetime | None = None, end: datetime | None = None, page: int = 1, page_size: int = 100):
        q = guard(SearchQuery, text=text, phone=phone, email=email, sha256=sha256, categories=category, start=start,
                  end=end, page=page, page_size=page_size)
        r = guard(ctx.search.search, a, case_id, q)
        return {"total": r.total, "page": r.page, "pages": r.pages,
                "hits": [{"id": h.artifact_id, "category": h.category, "timestamp": h.timestamp.isoformat() if h.timestamp else None,
                          "summary": h.summary, "evidence": h.evidence_uid, "source_path": h.source_path,
                          "source_table": h.source_table, "source_rowid": h.source_rowid, "parser": h.parser}
                         for h in r.hits], "files": r.file_hits}

    @app.get("/cases/{case_id}/correlations")
    def correlations(case_id: int, a=Depends(actor)):
        return [{"kind": c.kind, "rule": c.rule, "description": c.description, "artifacts": c.artifact_ids}
                for c in guard(ctx.correlation.correlations, a, case_id)]

    @app.post("/cases/{case_id}/verify")
    def verify(case_id: int, a=Depends(actor)):
        return [{"evidence_id": c.evidence_id, "ok": c.ok, "expected": c.expected, "observed": c.observed}
                for c in guard(ctx.evidence.verify_case, a, case_id, "api")]

    @app.get("/audit/verify")
    def audit_verify(a=Depends(actor)):
        from ..core.rbac import Perm
        guard(ctx.cases.authorize, a, Perm.VIEW_AUDIT)
        ok, broken, n = ctx.audit.verify_chain()
        return {"intact": ok, "first_broken_entry": broken, "entries": n, "head_hash": ctx.audit.head_hash()}

    return app


def ensure_loopback(host: str) -> None:
    import os
    if os.environ.get("LUNATIC_API_ALLOW_REMOTE") == "1":
        return
    try:
        ok = ipaddress.ip_address(host).is_loopback
    except ValueError:
        ok = host == "localhost"
    if not ok:
        raise ValidationError("The API only binds to loopback addresses (set LUNATIC_API_ALLOW_REMOTE=1 behind a "
                              "TLS reverse proxy if a remote deployment is formally approved).")


def run(ctx, host: str = "127.0.0.1", port: int = 8765) -> None:
    ensure_loopback(host)
    import uvicorn
    uvicorn.run(create_app(ctx), host=host, port=port, log_level="info")
