"""Persistence layer: bridges ForensicReport <-> Analysis/Hop/Anomaly rows.

Kept as plain functions over a Session rather than a repository class --
there's exactly one backing store and no need for the indirection a
repository pattern buys you.
"""

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.forensics.models import (
    Anomaly as AnomalyReport,
)
from app.forensics.models import (
    AuthenticationSummary,
    DomainIntel,
    ForensicReport,
    ParsedEmailMeta,
    RelayHop,
)
from app.models.analysis import Analysis, Anomaly, Hop
from app.schemas.analysis import AnalysisDetail, AnalysisSummary, AnomalyOut, HopOut

_SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def create_pending_analysis(db: Session, *, raw: bytes, filename: str) -> Analysis:
    """Insert a placeholder row before a batch/async job has run, so the
    caller has an id to poll immediately."""
    analysis = Analysis(
        filename=filename,
        sha256="",
        source_format="eml",
        raw_bytes=raw,
        status="pending",
        parse_confidence=0.0,
        dmarc_policy="unknown",
        meta_json={},
        authentication_json={},
    )
    db.add(analysis)
    db.flush()
    return analysis


def complete_analysis(db: Session, analysis: Analysis, report: ForensicReport) -> Analysis:
    """Populate (or overwrite) an Analysis row's fields from a finished report."""
    auth = report.authentication
    highest_severity = _highest_severity(report.anomalies)

    analysis.filename = report.filename
    analysis.sha256 = report.meta.sha256
    analysis.source_format = report.meta.source_format
    analysis.status = "complete"
    analysis.status_detail = None
    analysis.parse_confidence = report.meta.parse_confidence
    analysis.from_display_name = report.meta.from_display_name
    analysis.from_address = report.meta.from_address
    analysis.subject = report.meta.subject
    analysis.message_date = report.meta.date_parsed
    analysis.spf_result = auth.spf.result if auth.spf else None
    analysis.dkim_result = auth.dkim.result if auth.dkim else None
    analysis.dmarc_result = auth.dmarc.result if auth.dmarc else None
    analysis.dmarc_policy = auth.dmarc_policy
    analysis.dkim_signature_expired = auth.dkim_signature_expired
    analysis.hop_count = report.hop_count
    analysis.anomaly_count = len(report.anomalies)
    analysis.highest_anomaly_severity = highest_severity
    analysis.meta_json = report.meta.model_dump(mode="json")
    analysis.authentication_json = auth.model_dump(mode="json")
    analysis.sender_domain_intel_json = (
        report.sender_domain_intel.model_dump(mode="json") if report.sender_domain_intel else None
    )

    analysis.hops = [
        Hop(
            sequence=hop.sequence,
            raw_header=hop.raw_header,
            from_host=hop.from_host,
            from_ip=hop.from_ip,
            by_host=hop.by_host,
            protocol=hop.protocol,
            timestamp_raw=hop.timestamp_raw,
            timestamp=hop.timestamp,
            parse_confidence=hop.parse_confidence,
            asn=hop.asn,
            asn_org=hop.asn_org,
            country=hop.country,
            city=hop.city,
            latitude=hop.latitude,
            longitude=hop.longitude,
            enrichment_source=hop.enrichment_source,
            is_bogon=hop.is_bogon,
        )
        for hop in report.hops
    ]
    analysis.anomalies = [
        Anomaly(
            type=anomaly.type,
            severity=anomaly.severity,
            hop_sequences=anomaly.hop_sequences,
            summary=anomaly.summary,
            evidence=anomaly.evidence,
        )
        for anomaly in report.anomalies
    ]

    db.flush()
    return analysis


def fail_analysis(db: Session, analysis: Analysis, detail: str) -> Analysis:
    analysis.status = "failed"
    analysis.status_detail = detail[:1024]
    db.flush()
    return analysis


def create_completed_analysis(db: Session, *, raw: bytes, filename: str, report: ForensicReport) -> Analysis:
    analysis = create_pending_analysis(db, raw=raw, filename=filename)
    return complete_analysis(db, analysis, report)


def get_analysis(db: Session, analysis_id: uuid.UUID) -> Analysis | None:
    return db.get(Analysis, analysis_id)


def list_analyses(
    db: Session,
    *,
    limit: int = 25,
    offset: int = 0,
    status: str | None = None,
    spf_result: str | None = None,
    dkim_result: str | None = None,
    dmarc_result: str | None = None,
) -> tuple[Sequence[Analysis], int]:
    stmt = select(Analysis)
    count_stmt = select(func.count()).select_from(Analysis)

    if status:
        stmt = stmt.where(Analysis.status == status)
        count_stmt = count_stmt.where(Analysis.status == status)
    if spf_result:
        stmt = stmt.where(Analysis.spf_result == spf_result)
        count_stmt = count_stmt.where(Analysis.spf_result == spf_result)
    if dkim_result:
        stmt = stmt.where(Analysis.dkim_result == dkim_result)
        count_stmt = count_stmt.where(Analysis.dkim_result == dkim_result)
    if dmarc_result:
        stmt = stmt.where(Analysis.dmarc_result == dmarc_result)
        count_stmt = count_stmt.where(Analysis.dmarc_result == dmarc_result)

    stmt = stmt.order_by(Analysis.created_at.desc()).limit(limit).offset(offset)

    total = db.scalar(count_stmt) or 0
    rows = db.scalars(stmt).all()
    return rows, total


def to_analysis_detail(analysis: Analysis) -> AnalysisDetail:
    """Assemble the full API response for one analysis from its ORM row.

    The flat fields map 1:1 onto Analysis columns (AnalysisSummary uses
    from_attributes for those); meta/authentication/sender_domain_intel are
    stored as JSONB and re-validated back into their canonical forensics
    models here since the ORM column names (``meta_json``) don't match the
    response field names (``meta``) that from_attributes would need.
    """
    return AnalysisDetail(
        **AnalysisSummary.model_validate(analysis).model_dump(),
        meta=ParsedEmailMeta.model_validate(analysis.meta_json),
        authentication=AuthenticationSummary.model_validate(analysis.authentication_json),
        hops=[HopOut.model_validate(hop) for hop in analysis.hops],
        anomalies=[AnomalyOut.model_validate(a) for a in analysis.anomalies],
        sender_domain_intel=(
            DomainIntel.model_validate(analysis.sender_domain_intel_json)
            if analysis.sender_domain_intel_json
            else None
        ),
    )


def to_forensic_report(analysis: Analysis) -> ForensicReport:
    """Reassemble the canonical ForensicReport domain model from DB rows.

    Used by the export endpoint, which reuses the exact same text/JSON
    renderers the CLI uses -- so a report looks identical whether it was
    just generated or reloaded from the database days later.
    """
    return ForensicReport(
        filename=analysis.filename,
        meta=ParsedEmailMeta.model_validate(analysis.meta_json),
        authentication=AuthenticationSummary.model_validate(analysis.authentication_json),
        hops=[
            RelayHop(
                sequence=hop.sequence,
                raw_header=hop.raw_header,
                from_host=hop.from_host,
                from_ip=hop.from_ip,
                by_host=hop.by_host,
                protocol=hop.protocol,
                timestamp_raw=hop.timestamp_raw,
                timestamp=hop.timestamp,
                parse_confidence=hop.parse_confidence,
                asn=hop.asn,
                asn_org=hop.asn_org,
                country=hop.country,
                city=hop.city,
                latitude=hop.latitude,
                longitude=hop.longitude,
                enrichment_source=hop.enrichment_source,
                is_bogon=hop.is_bogon,
            )
            for hop in analysis.hops
        ],
        anomalies=[
            AnomalyReport(
                type=anomaly.type,
                severity=anomaly.severity,
                hop_sequences=anomaly.hop_sequences,
                summary=anomaly.summary,
                evidence=anomaly.evidence,
            )
            for anomaly in analysis.anomalies
        ],
        hop_count=analysis.hop_count,
        sender_domain_intel=(
            DomainIntel.model_validate(analysis.sender_domain_intel_json)
            if analysis.sender_domain_intel_json
            else None
        ),
        generated_at=analysis.created_at,
    )


def _highest_severity(anomalies: Sequence[AnomalyReport]) -> str | None:
    if not anomalies:
        return None
    return max((a.severity for a in anomalies), key=lambda s: _SEVERITY_RANK[s])
