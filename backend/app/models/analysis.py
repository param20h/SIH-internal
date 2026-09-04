"""SQLAlchemy models for persisted forensic analyses.

Schema shape: Analysis holds the normalized, queryable top-level fields
(authentication verdicts, hop count, parse confidence) plus the full
ParsedEmailMeta as JSON for fidelity without needing a table per nested
field. Hop and Anomaly are fully normalized tables -- Phase 3's relay-path
map and indicator panel both need to query per-hop and per-anomaly data
directly, so those two earn real tables now. An IOC table is deliberately
not added yet: nothing before Phase 5 populates one, and an unused table is
premature schema.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.db import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    source_format: Mapped[str] = mapped_column(String(8))
    raw_bytes: Mapped[bytes] = mapped_column(LargeBinary)

    status: Mapped[str] = mapped_column(String(16), default="complete", index=True)
    status_detail: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    parse_confidence: Mapped[float] = mapped_column(default=0.0)
    from_display_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    from_address: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    subject: Mapped[str | None] = mapped_column(String(998), nullable=True)
    message_date: Mapped[datetime | None] = mapped_column(nullable=True)

    spf_result: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    dkim_result: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    dmarc_result: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    dmarc_policy: Mapped[str] = mapped_column(String(16), default="unknown")
    dkim_signature_expired: Mapped[bool] = mapped_column(default=False)

    # risk_score/verdict are normalized for filtering & stats; the full
    # explainable factor breakdown is not persisted separately -- it's a
    # pure function of authentication_json + the anomalies table +
    # ai_signals_json, so it's recomputed on read (see
    # crud.to_analysis_detail) rather than stored twice.
    risk_score: Mapped[int] = mapped_column(default=0, index=True)
    verdict: Mapped[str] = mapped_column(String(16), default="clean", index=True)

    hop_count: Mapped[int] = mapped_column(default=0)
    anomaly_count: Mapped[int] = mapped_column(default=0)
    highest_anomaly_severity: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)

    # Normalized for filtering/stats; None for rows analyzed before Phase 4
    # (no phishing-classifier verdict exists for them) or when the model
    # simply wasn't present at analysis time.
    phishing_probability: Mapped[float | None] = mapped_column(nullable=True, index=True)

    meta_json: Mapped[dict[str, Any]] = mapped_column(JSONB)
    authentication_json: Mapped[dict[str, Any]] = mapped_column(JSONB)
    sender_domain_intel_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Nullable: rows analyzed before Phase 4 predate this signal bundle
    # entirely. See crud._DEFAULT_AI_SIGNALS for the reconstruction
    # fallback used for such rows.
    ai_signals_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Free-text case notes an analyst can attach, surfaced on the forensic
    # PDF report's "analyst notes" field. Not computed from the message --
    # a human writes this, so it's simply persisted and returned as-is.
    analyst_notes: Mapped[str | None] = mapped_column(String(4096), nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)

    hops: Mapped[list["Hop"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", order_by="Hop.sequence"
    )
    anomalies: Mapped[list["Anomaly"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )


class Hop(Base):
    __tablename__ = "hops"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    sequence: Mapped[int] = mapped_column()
    raw_header: Mapped[str] = mapped_column(String)
    from_host: Mapped[str | None] = mapped_column(String(512), nullable=True)
    from_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    by_host: Mapped[str | None] = mapped_column(String(512), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp_raw: Mapped[str | None] = mapped_column(String(256), nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(nullable=True)
    parse_confidence: Mapped[float] = mapped_column(default=0.0)

    asn: Mapped[int | None] = mapped_column(nullable=True)
    asn_org: Mapped[str | None] = mapped_column(String(256), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latitude: Mapped[float | None] = mapped_column(nullable=True)
    longitude: Mapped[float | None] = mapped_column(nullable=True)
    enrichment_source: Mapped[str] = mapped_column(String(24), default="unavailable")
    is_bogon: Mapped[bool] = mapped_column(default=False)

    analysis: Mapped[Analysis] = relationship(back_populates="hops")


class Anomaly(Base):
    __tablename__ = "anomalies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    hop_sequences: Mapped[list[int]] = mapped_column(JSONB)
    summary: Mapped[str] = mapped_column(String(1024))
    evidence: Mapped[str] = mapped_column(String)

    analysis: Mapped[Analysis] = relationship(back_populates="anomalies")
