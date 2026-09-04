"""Confidence-scored origin attribution.

Best-guess originating network for a message, with a stated confidence
level and the specific reasoning behind it -- not a bare claim. This is
the module the hard constraint "never claim certainty the evidence
doesn't support" bears on most directly: every branch here either names
concrete evidence for its confidence level or explicitly says why
confidence is low/unavailable, and the confidence level itself is capped
by the weakest link in the chain (relay-chain forgery signals always cap
confidence at "low," no matter how good the GeoIP enrichment looks).
"""

from app.forensics.models import (
    Anomaly,
    AttributionConfidence,
    AuthResult,
    OriginAttribution,
    RelayHop,
)

_FORGERY_ANOMALY_TYPES = {"forged_internal_origin", "negative_time_delta"}


def attribute_origin(
    hops: list[RelayHop], anomalies: list[Anomaly], spf: AuthResult | None
) -> OriginAttribution:
    candidate = _earliest_public_hop(hops)
    if candidate is None:
        return OriginAttribution(
            source="unavailable",
            confidence="unknown",
            reasoning=(
                "no hop in the reconstructed relay chain reports a public, non-bogon "
                "source IP -- there is nothing to attribute an origin to"
            ),
        )

    reasoning_parts = [
        f"earliest hop reporting a public source IP is hop #{candidate.sequence} "
        f"({candidate.from_ip}, claimed sending host {candidate.from_host or 'unknown'})."
    ]

    has_enrichment = candidate.enrichment_source == "geolite2-local"
    if has_enrichment:
        reasoning_parts.append(
            f"GeoIP enrichment attributes this address to "
            f"{candidate.asn_org or 'an unnamed organization'} "
            f"(AS{candidate.asn if candidate.asn is not None else '?'}), "
            f"{candidate.country or 'unknown country'}."
        )
    else:
        reasoning_parts.append(
            "no GeoIP enrichment is available for this address (see data/geoip/README.md) "
            "-- the IP itself is reported, but no network/organization name can be attached."
        )

    forgery_signals = [
        a
        for a in anomalies
        if a.type in _FORGERY_ANOMALY_TYPES and any(seq <= candidate.sequence for seq in a.hop_sequences)
    ]
    if forgery_signals:
        types = sorted({a.type for a in forgery_signals})
        verb = "affects" if len(forgery_signals) == 1 else "affect"
        reasoning_parts.append(
            f"confidence is capped at 'low': {len(forgery_signals)} relay-chain "
            f"anomal{'y' if len(forgery_signals) == 1 else 'ies'} ({', '.join(types)}) {verb} this "
            "hop or an earlier one, meaning the chain itself may have been tampered with -- this "
            "candidate could be a forged claim, not the true origin."
        )

    if spf is not None:
        if spf.result == "fail":
            reasoning_parts.append(
                "SPF failed for the claimed sending domain, meaning this connecting IP was not "
                "authorized by that domain -- consistent with (though not proof of) this being an "
                "unauthorized true origin rather than a legitimate relay."
            )
        elif spf.result == "pass":
            reasoning_parts.append(
                "SPF passed, corroborating that this hop's IP is an authorized sender for the "
                "claimed domain."
            )

    confidence: AttributionConfidence
    if forgery_signals:
        confidence = "low"
    elif has_enrichment:
        confidence = "high"
    else:
        confidence = "medium"

    return OriginAttribution(
        source="heuristic",
        origin_ip=candidate.from_ip,
        origin_hop_sequence=candidate.sequence,
        asn=candidate.asn,
        asn_org=candidate.asn_org,
        country=candidate.country,
        confidence=confidence,
        reasoning=" ".join(reasoning_parts),
    )


def _earliest_public_hop(hops: list[RelayHop]) -> RelayHop | None:
    for hop in hops:
        if hop.from_ip and not hop.is_bogon:
            return hop
    return None
