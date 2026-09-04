from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from app.core.db import get_db
from app.models.analysis import Analysis, Anomaly
from app.schemas.analysis import StatsResponse

router = APIRouter(tags=["stats"])


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)) -> StatsResponse:
    total = db.scalar(select(func.count()).select_from(Analysis)) or 0

    status_breakdown = _count_by(db, Analysis.status)
    verdict_breakdown = _count_by(db, Analysis.verdict)
    spf_breakdown = _count_by(db, Analysis.spf_result)
    dkim_breakdown = _count_by(db, Analysis.dkim_result)
    dmarc_breakdown = _count_by(db, Analysis.dmarc_result)
    anomaly_type_breakdown = _count_by(db, Anomaly.type)
    anomaly_severity_breakdown = _count_by(db, Anomaly.severity)

    since = datetime.now(tz=UTC) - timedelta(hours=24)
    last_24h = db.scalar(
        select(func.count()).select_from(Analysis).where(Analysis.created_at >= since)
    ) or 0

    return StatsResponse(
        total_analyses=total,
        status_breakdown=status_breakdown,
        verdict_breakdown=verdict_breakdown,
        spf_breakdown=spf_breakdown,
        dkim_breakdown=dkim_breakdown,
        dmarc_breakdown=dmarc_breakdown,
        anomaly_type_breakdown=anomaly_type_breakdown,
        anomaly_severity_breakdown=anomaly_severity_breakdown,
        analyses_last_24h=last_24h,
    )


def _count_by(db: Session, column: InstrumentedAttribute[Any]) -> dict[str, int]:
    stmt = select(column, func.count()).group_by(column)
    rows = db.execute(stmt).all()
    return {str(key): count for key, count in rows if key is not None}
