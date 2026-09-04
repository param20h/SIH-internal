"""Pydantic schemas for the deterministic forensics engine.

These models are the contract between the parsing/analysis stages and
everything downstream (API responses, CLI output, PDF export). Every field
that feeds a verdict carries the raw evidence it was derived from — nothing
here is allowed to be a bare, unexplained score.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.ai.models import AiSignals
from app.forensics.rdap import DomainIntel

__all__ = [
    "AiSignals",
    "Anomaly",
    "AnomalySeverity",
    "AnomalyType",
    "AttachmentInfo",
    "AttributionConfidence",
    "AuthMechanism",
    "AuthResult",
    "AuthResultValue",
    "AuthenticationSummary",
    "DomainIntel",
    "ForensicReport",
    "OriginAttribution",
    "ParseIssue",
    "ParsedEmailMeta",
    "RelayHop",
    "RiskScore",
    "ScoreCategory",
    "ScoreFactor",
    "Verdict",
]

AuthMechanism = Literal["spf", "dkim", "dmarc"]
AuthResultValue = Literal[
    "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "unknown"
]
AnomalySeverity = Literal["info", "low", "medium", "high", "critical"]
AnomalyType = Literal[
    "negative_time_delta",
    "impossible_timestamp",
    "bogon_ip_in_path",
    "hop_count_outlier",
    "forged_internal_origin",
    "missing_expected_field",
    "large_timezone_jump",
    "dkim_signature_expired",
]


class ParseIssue(BaseModel):
    """A single problem encountered while parsing, kept even though parsing continued."""

    field: str
    detail: str


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str | None = None
    size_bytes: int
    sha256: str


class ParsedEmailMeta(BaseModel):
    from_display_name: str | None = None
    from_address: str | None = None
    to_addresses: list[str] = Field(default_factory=list)
    subject: str | None = None
    date_raw: str | None = None
    date_parsed: datetime | None = None
    message_id: str | None = None
    return_path: str | None = None
    content_type: str | None = None
    has_attachments: bool = False
    attachment_names: list[str] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    parse_confidence: float = Field(ge=0.0, le=1.0)
    issues: list[ParseIssue] = Field(default_factory=list)
    source_format: Literal["eml", "msg"]
    sha256: str


class AuthResult(BaseModel):
    mechanism: AuthMechanism
    result: AuthResultValue
    reason: str | None = None
    domain: str | None = None
    raw_segment: str


class AuthenticationSummary(BaseModel):
    spf: AuthResult | None = None
    dkim: AuthResult | None = None
    dmarc: AuthResult | None = None
    source: Literal["authentication-results-header", "unavailable"]
    raw_header: str | None = None
    dkim_signature_present: bool = False
    dkim_signature_expired: bool = False
    dkim_expiry: datetime | None = None
    dmarc_policy: Literal["none", "quarantine", "reject", "unknown"] = "unknown"


class RelayHop(BaseModel):
    sequence: int
    raw_header: str
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    protocol: str | None = None
    timestamp_raw: str | None = None
    timestamp: datetime | None = None
    parse_confidence: float = Field(ge=0.0, le=1.0)

    # Enrichment, filled in separately; always present but nullable so the
    # deterministic chain reconstruction never depends on it.
    asn: int | None = None
    asn_org: str | None = None
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    enrichment_source: Literal["geolite2-local", "unavailable"] = "unavailable"
    is_bogon: bool = False


class Anomaly(BaseModel):
    type: AnomalyType
    severity: AnomalySeverity
    hop_sequences: list[int]
    summary: str
    evidence: str


ScoreCategory = Literal[
    "authentication", "relay_chain", "phishing_classifier", "lookalike_domain", "url_analysis", "ai_text"
]
Verdict = Literal["clean", "suspicious", "malicious"]


class ScoreFactor(BaseModel):
    """One named, weighted contribution to the risk score.

    The hard constraint this exists to satisfy: no black-box score. Every
    point in RiskScore.score must trace back to one of these, each
    carrying the raw evidence that justified it.
    """

    name: str
    weight: int
    evidence: str
    category: ScoreCategory


class RiskScore(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    factors: list[ScoreFactor]


AttributionConfidence = Literal["low", "medium", "high", "unknown"]


class OriginAttribution(BaseModel):
    """Defined here, not in app/attribution/origin.py where it's produced:
    attribute_origin() is tightly coupled to RelayHop/Anomaly/AuthResult
    (it walks the relay chain directly), so it already depends on this
    module -- defining the type here too keeps that a one-directional
    dependency (attribution -> forensics.models) instead of circular,
    the same reasoning that put DomainIntel in forensics/rdap.py."""

    source: Literal["heuristic", "unavailable"]
    origin_ip: str | None = None
    origin_hop_sequence: int | None = None
    asn: int | None = None
    asn_org: str | None = None
    country: str | None = None
    confidence: AttributionConfidence = "unknown"
    reasoning: str


class ForensicReport(BaseModel):
    filename: str
    meta: ParsedEmailMeta
    authentication: AuthenticationSummary
    hops: list[RelayHop]
    anomalies: list[Anomaly]
    hop_count: int
    risk: RiskScore
    sender_domain_intel: DomainIntel | None = None
    ai_signals: AiSignals
    attribution: OriginAttribution
    generated_at: datetime
