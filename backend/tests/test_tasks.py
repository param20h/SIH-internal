"""Tests for the Celery task itself.

Deliberately does not use the transactional db_session fixture: the task
opens its own SessionLocal() bound to the real engine (exactly as it does
in production), which is a different connection than the fixture's, so
the fixture's uncommitted rows would be invisible to it. Instead this
talks to the real database directly and cleans up explicitly.
"""

import uuid
from pathlib import Path

from app import crud
from app.core.db import SessionLocal
from app.tasks import analyze_email_task

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "data" / "samples"


def test_analyze_email_task_completes_pending_analysis() -> None:
    db = SessionLocal()
    analysis_id: uuid.UUID | None = None
    try:
        raw = (SAMPLES_DIR / "03_spf_fail_spoofed_bank.eml").read_bytes()
        analysis = crud.create_pending_analysis(db, raw=raw, filename="03.eml")
        db.commit()
        analysis_id = analysis.id

        result_status = analyze_email_task.run(str(analysis_id))

        db.expire_all()
        refreshed = crud.get_analysis(db, analysis_id)
        assert refreshed is not None
        assert refreshed.status == "complete"
        assert refreshed.spf_result == "fail"
        assert result_status == "complete"
    finally:
        if analysis_id is not None:
            leftover = crud.get_analysis(db, analysis_id)
            if leftover is not None:
                db.delete(leftover)
                db.commit()
        db.close()


def test_analyze_email_task_unknown_id_returns_not_found() -> None:
    result = analyze_email_task.run(str(uuid.uuid4()))
    assert result == "not_found"
