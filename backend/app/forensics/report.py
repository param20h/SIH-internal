"""Top-level orchestration: raw email bytes in, a full ForensicReport out.

This is the one function the API layer, the Celery worker, and the CLI all
call. It never raises -- every stage it composes is individually designed
to degrade rather than throw, so a malformed or hostile input still
produces a usable (if low-confidence) report instead of a 500.
"""

from datetime import UTC, datetime

from app.forensics.anomalies import detect_anomalies
from app.forensics.auth import extract_authentication
from app.forensics.geoip import enrich_hops
from app.forensics.models import Anomaly, DomainIntel, ForensicReport
from app.forensics.parser import parse_email_bytes
from app.forensics.rdap import lookup_domain_age
from app.forensics.relay_chain import parse_relay_chain
from app.scoring.engine import compute_risk_score


def generate_report(
    raw: bytes,
    filename: str,
    *,
    geoip_city_db_path: str | None = None,
    geoip_asn_db_path: str | None = None,
    enable_network_enrichment: bool = False,
) -> ForensicReport:
    message, meta = parse_email_bytes(raw, filename)

    authentication = extract_authentication(message, meta.date_parsed)

    hops = parse_relay_chain(message)
    if geoip_city_db_path:
        hops = enrich_hops(hops, geoip_city_db_path, geoip_asn_db_path)

    anomalies = detect_anomalies(hops)
    if authentication.dkim_signature_expired:
        anomalies.append(_dkim_expired_anomaly(authentication.dkim_expiry))

    sender_domain_intel = _lookup_sender_domain(meta.from_address, enable_network_enrichment)
    risk = compute_risk_score(authentication, anomalies)

    return ForensicReport(
        filename=filename,
        meta=meta,
        authentication=authentication,
        hops=hops,
        anomalies=anomalies,
        hop_count=len(hops),
        risk=risk,
        sender_domain_intel=sender_domain_intel,
        generated_at=datetime.now(tz=UTC),
    )


def _dkim_expired_anomaly(expiry: datetime | None) -> Anomaly:
    detail = f"signature expiration (x=) tag {expiry.isoformat()}" if expiry else "signature expiration tag"
    return Anomaly(
        type="dkim_signature_expired",
        severity="medium",
        hop_sequences=[],
        summary="DKIM signature is expired",
        evidence=(
            f"The message's {detail} is in the past relative to the message Date -- "
            "the signature is well-formed but must be treated as failed, not trusted"
        ),
    )


def _lookup_sender_domain(from_address: str | None, enable_network: bool) -> DomainIntel | None:
    if not from_address or "@" not in from_address:
        return None
    domain = from_address.rsplit("@", 1)[-1]
    if not domain:
        return None
    return lookup_domain_age(domain, enable_network=enable_network)
