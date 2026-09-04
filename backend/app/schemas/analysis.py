import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.ai.models import AiSignals
from app.forensics.models import (
    AuthenticationSummary,
    DomainIntel,
    OriginAttribution,
    ParsedEmailMeta,
    RiskScore,
    Verdict,
)

AnalysisStatus = Literal["pending", "processing", "complete", "failed"]


class HopOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    sequence: int
    raw_header: str
    from_host: str | None
    from_ip: str | None
    by_host: str | None
    protocol: str | None
    timestamp_raw: str | None
    timestamp: datetime | None
    parse_confidence: float
    asn: int | None
    asn_org: str | None
    country: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    enrichment_source: str
    is_bogon: bool


class AnomalyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    type: str
    severity: str
    hop_sequences: list[int]
    summary: str
    evidence: str


class AnalysisSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    filename: str
    source_format: str
    status: AnalysisStatus
    status_detail: str | None
    parse_confidence: float
    from_display_name: str | None
    from_address: str | None
    subject: str | None
    message_date: datetime | None
    spf_result: str | None
    dkim_result: str | None
    dmarc_result: str | None
    dmarc_policy: str
    dkim_signature_expired: bool
    risk_score: int
    verdict: Verdict
    hop_count: int
    anomaly_count: int
    highest_anomaly_severity: str | None
    phishing_probability: float | None
    analyst_notes: str | None
    created_at: datetime


class AnalysisDetail(AnalysisSummary):
    meta: ParsedEmailMeta
    authentication: AuthenticationSummary
    hops: list[HopOut]
    anomalies: list[AnomalyOut]
    risk: RiskScore
    sender_domain_intel: DomainIntel | None
    ai_signals: AiSignals
    attribution: OriginAttribution


class AnalysisListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AnalysisSummary]


class BatchUploadItem(BaseModel):
    analysis_id: uuid.UUID
    filename: str
    status: AnalysisStatus


class SkippedUpload(BaseModel):
    filename: str
    reason: str


class BatchUploadResponse(BaseModel):
    items: list[BatchUploadItem]
    skipped: list[SkippedUpload]


class StatsResponse(BaseModel):
    total_analyses: int
    status_breakdown: dict[str, int]
    verdict_breakdown: dict[str, int]
    spf_breakdown: dict[str, int]
    dkim_breakdown: dict[str, int]
    dmarc_breakdown: dict[str, int]
    anomaly_type_breakdown: dict[str, int]
    anomaly_severity_breakdown: dict[str, int]
    analyses_last_24h: int
