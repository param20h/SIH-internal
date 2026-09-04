"""Demo-day seeding: wipes existing analyses and re-ingests the full
sample corpus through the exact same generate_report() / crud pipeline a
real upload goes through -- no synthetic rows, no shortcuts, so what the
demo shows is provably what the app actually does with these files.

Idempotent: safe to re-run right before a live demo to reset to a known,
clean state. Runs with enable_network_enrichment=False, same as every
real upload path -- this is also the offline-mode verification described
in docs/DEMO.md, not a separate code path.

    docker compose run --rm api python -m app.scripts.seed_demo
"""

import sys
from pathlib import Path

from app import crud
from app.core.config import get_settings
from app.core.db import SessionLocal
from app.forensics.report import generate_report
from app.models.analysis import Analysis

_SAMPLES_DIR = Path("/data/samples")


def main() -> int:
    sample_paths = sorted(_SAMPLES_DIR.glob("*.eml"))
    if not sample_paths:
        print(f"error: no .eml files found in {_SAMPLES_DIR}", file=sys.stderr)
        return 1

    settings = get_settings()
    db = SessionLocal()
    try:
        deleted = db.query(Analysis).delete()
        db.commit()
        print(f"cleared {deleted} existing analysis row(s)")

        verdict_counts: dict[str, int] = {}
        for path in sample_paths:
            raw = path.read_bytes()
            report = generate_report(
                raw,
                filename=path.name,
                geoip_city_db_path=settings.geolite2_city_db_path,
                geoip_asn_db_path=settings.geolite2_asn_db_path,
                enable_network_enrichment=False,
            )
            crud.create_completed_analysis(db, raw=raw, filename=path.name, report=report)
            db.commit()
            verdict_counts[report.risk.verdict] = verdict_counts.get(report.risk.verdict, 0) + 1
            print(f"  seeded {path.name} -> {report.risk.verdict} ({report.risk.score}/100)")

        print(f"\nseeded {len(sample_paths)} analyses: {verdict_counts}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
