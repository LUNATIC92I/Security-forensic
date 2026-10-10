"""Regenerate examples/sample_report.{pdf,html} from the synthetic scenario (no real data)."""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lunatic_forensics import synthetic as S  # noqa: E402
from lunatic_forensics.core.config import AppConfig  # noqa: E402
from lunatic_forensics.services.context import AppContext  # noqa: E402
from lunatic_forensics.services.search_service import SearchQuery  # noqa: E402

PW = "Demo!Passw0rd-2026"


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="lunatic_demo_"))
    ctx = AppContext(AppConfig(home=tmp / "home"), passphrase="Demo master passphrase 1!")
    ctx.auth.bootstrap_admin("admin", PW, "Lab administrator")
    admin = ctx.auth.authenticate("admin", PW)
    ctx.auth.create_user(admin, "j.examiner", PW, "investigator", "Jordan Examiner (synthetic)")
    inv = ctx.auth.authenticate("j.examiner", PW)
    cid = ctx.cases.create(inv, "Operation SYNTHESE (demonstration)",
                           "Fully synthetic demonstration case. All persons, numbers and messages are fictitious.",
                           "Synthetic requisition SYN-2026-001", "Smartphone of the fictitious person 'Alex Martin': "
                           "communications 2026-03-14 to 2026-03-17", "Europe/Paris")
    for key, p in S.build_demo_dataset(tmp / "dataset").items():
        ev = ctx.evidence.import_evidence(inv, cid, p, acquisition_method=f"synthetic {key}",
                                          tool_name="synthetic generator", tool_version="0.1.0")
        ctx.analysis.run(inv, ev, correlate=False)
    ctx.correlation.rebuild(inv, cid)
    msgs = ctx.search.search(inv, cid, SearchQuery(text="10h devant la gare", deep=True)).hits
    calls = ctx.search.search(inv, cid, SearchQuery(phone="+33639980001", categories=["call"])).hits
    geo = ctx.search.search(inv, cid, SearchQuery(min_lat=48.84, max_lat=48.85, min_lon=2.37, max_lon=2.38)).hits
    ctx.findings.add(inv, cid, "fact", "Meeting arranged with Bob Durand",
                     "Outgoing messages set a meeting 'at 10h in front of the station' with +33639980001.",
                     [h.artifact_id for h in msgs])
    ctx.findings.add(inv, cid, "fact", "Calls with the same counterpart",
                     "Call log entries with +33639980001 on 2026-03-14 and 2026-03-15.", [h.artifact_id for h in calls])
    ctx.findings.add(inv, cid, "interpretation", "Device near the station on 2026-03-15",
                     "Photo EXIF GPS and location history place the device around 48.844 N, 2.374 E at about 10:55 UTC.",
                     [h.artifact_id for h in geo])
    ctx.findings.add(inv, cid, "hypothesis", "The planned meeting took place",
                     "Consistent with the communications and locations above, but not demonstrated by the data.", [])
    out = ROOT / "examples"
    out.mkdir(exist_ok=True)
    pdf = ctx.reports.generate(inv, cid, "pdf", output=out / "sample_report.pdf")
    html = ctx.reports.generate(inv, cid, "html", output=out / "sample_report.html")
    ctx.close()
    shutil.rmtree(tmp, ignore_errors=True)
    print(pdf, html, sep="\n")


if __name__ == "__main__":
    main()
