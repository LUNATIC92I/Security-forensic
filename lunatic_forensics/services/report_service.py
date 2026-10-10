"""Report generation service (HTML / PDF), with hashing and audit of outputs."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import select

from ..core.errors import ValidationError
from ..core.hashing import sha256_file
from ..core.rbac import Perm
from ..core.timeutils import utcnow
from ..reports.data import build_report_data
from ..reports.html_report import render_html
from ..reports.pdf_report import render_pdf
from ..storage.models import Report
from .base import ServiceBase


class ReportService(ServiceBase):
    def generate(self, actor, case_id: int, fmt: str = "pdf", output: Path | None = None, max_rows: int = 200) -> Path:
        self.authorize(actor, Perm.GENERATE_REPORT)
        fmt = fmt.lower()
        if fmt not in ("pdf", "html"):
            raise ValidationError("Report format must be 'pdf' or 'html'.")
        with self.db.session() as s:
            case = self.case_for(s, actor, case_id)
            data = build_report_data(self.ctx, s, case_id, actor.username, max_rows=max_rows)
            out = Path(output) if output else (self.ctx.config.reports_dir / case.uid /
                                               f"report_{case.uid}_{utcnow().strftime('%Y%m%dT%H%M%SZ')}.{fmt}")
        out.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "html":
            out.write_text(render_html(data), encoding="utf-8")
        else:
            render_pdf(data, out)
        sha = sha256_file(out)
        with self.db.session() as s:
            s.add(Report(case_id=case_id, generated_by=actor.username, format=fmt, path=str(out), sha256=sha))
            self.ctx.audit.log("report.generate", actor, case_id=case_id, object_type="report", object_id=out.name,
                               details={"format": fmt, "sha256": sha}, session=s)
        return out

    def list(self, actor, case_id: int) -> list[Report]:
        self.authorize(actor, Perm.VIEW_CASE)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            return list(s.scalars(select(Report).where(Report.case_id == case_id).order_by(Report.generated_at.desc())))
