"""Celery tasks. Currently just the batch-upload analysis job."""

import uuid

from app import crud
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.db import SessionLocal
from app.forensics.report import generate_report


@celery_app.task(name="analyze_email")  # type: ignore[untyped-decorator]
def analyze_email_task(analysis_id: str) -> str:
    settings = get_settings()
    db = SessionLocal()
    try:
        analysis = crud.get_analysis(db, uuid.UUID(analysis_id))
        if analysis is None:
            return "not_found"

        try:
            report = generate_report(
                analysis.raw_bytes,
                filename=analysis.filename,
                geoip_city_db_path=settings.geolite2_city_db_path,
                enable_network_enrichment=False,
            )
            crud.complete_analysis(db, analysis, report)
        except Exception as exc:
            crud.fail_analysis(db, analysis, f"analysis failed: {exc!r}")

        db.commit()
        return analysis.status
    finally:
        db.close()
