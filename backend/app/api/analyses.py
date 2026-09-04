import uuid
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.orm import Session

from app import crud
from app.core.config import get_settings
from app.core.db import get_db
from app.forensics.render import render_text_report
from app.forensics.report import generate_report
from app.schemas.analysis import (
    AnalysisDetail,
    AnalysisListResponse,
    AnalysisStatus,
    AnalysisSummary,
    BatchUploadItem,
    BatchUploadResponse,
    SkippedUpload,
)
from app.tasks import analyze_email_task

router = APIRouter(prefix="/analyses", tags=["analyses"])


@router.post("", response_model=AnalysisDetail, status_code=201)
async def upload_and_analyze(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> AnalysisDetail:
    """Upload one .eml/.msg file and analyze it synchronously.

    The deterministic pipeline runs in well under a second per email (see
    Phase 1's corpus timing test), so a single upload doesn't need the
    Celery queue -- only batches do, below.
    """
    settings = get_settings()
    raw = await file.read()
    _validate_upload(raw, settings.upload_max_bytes)

    filename = file.filename or "upload.eml"
    report = generate_report(
        raw,
        filename=filename,
        geoip_city_db_path=settings.geolite2_city_db_path,
        geoip_asn_db_path=settings.geolite2_asn_db_path,
        enable_network_enrichment=False,
    )
    analysis = crud.create_completed_analysis(db, raw=raw, filename=filename, report=report)
    db.commit()
    return crud.to_analysis_detail(analysis)


@router.post("/batch", response_model=BatchUploadResponse, status_code=202)
async def upload_batch(
    files: list[UploadFile] = File(...),
    db: Session = Depends(get_db),
) -> BatchUploadResponse:
    """Upload multiple files; each is queued as a Celery job and analyzed
    asynchronously. Poll GET /analyses/{id} for each returned id."""
    settings = get_settings()
    items: list[BatchUploadItem] = []
    skipped: list[SkippedUpload] = []

    for upload in files:
        raw = await upload.read()
        filename = upload.filename or "upload.eml"
        try:
            _validate_upload(raw, settings.upload_max_bytes)
        except HTTPException as exc:
            skipped.append(SkippedUpload(filename=filename, reason=str(exc.detail)))
            continue

        analysis = crud.create_pending_analysis(db, raw=raw, filename=filename)
        db.commit()
        analyze_email_task.delay(str(analysis.id))
        items.append(BatchUploadItem(analysis_id=analysis.id, filename=filename, status="pending"))

    return BatchUploadResponse(items=items, skipped=skipped)


@router.get("", response_model=AnalysisListResponse)
def list_analyses(
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: AnalysisStatus | None = None,
    spf_result: str | None = None,
    dkim_result: str | None = None,
    dmarc_result: str | None = None,
    db: Session = Depends(get_db),
) -> AnalysisListResponse:
    rows, total = crud.list_analyses(
        db,
        limit=limit,
        offset=offset,
        status=status,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
    )
    return AnalysisListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[AnalysisSummary.model_validate(row) for row in rows],
    )


@router.get("/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(analysis_id: uuid.UUID, db: Session = Depends(get_db)) -> AnalysisDetail:
    analysis = crud.get_analysis(db, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return crud.to_analysis_detail(analysis)


@router.get("/{analysis_id}/export")
def export_analysis(
    analysis_id: uuid.UUID,
    format: Literal["json", "txt"] = "json",
    db: Session = Depends(get_db),
) -> Response:
    analysis = crud.get_analysis(db, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    if analysis.status != "complete":
        raise HTTPException(status_code=409, detail=f"analysis is {analysis.status}, not complete yet")

    report = crud.to_forensic_report(analysis)
    base_name = analysis.filename.rsplit(".", 1)[0] or str(analysis_id)

    if format == "txt":
        content = render_text_report(report)
        headers = {"Content-Disposition": f'attachment; filename="{base_name}_tva_report.txt"'}
        return PlainTextResponse(content, headers=headers)

    content = report.model_dump_json(indent=2)
    headers = {"Content-Disposition": f'attachment; filename="{base_name}_tva_report.json"'}
    return Response(content, media_type="application/json", headers=headers)


def _validate_upload(raw: bytes, max_bytes: int) -> None:
    if not raw:
        raise HTTPException(status_code=400, detail="uploaded file is empty")
    if len(raw) > max_bytes:
        raise HTTPException(
            status_code=413, detail=f"file exceeds the {max_bytes} byte upload limit"
        )
