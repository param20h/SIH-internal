from datetime import UTC, datetime

from app.attribution.origin import attribute_origin
from app.forensics.models import Anomaly, AuthResult, RelayHop


def _hop(sequence: int, **overrides: object) -> RelayHop:
    defaults: dict[str, object] = {
        "sequence": sequence,
        "raw_header": f"hop {sequence}",
        "from_host": f"host{sequence}.example.test",
        "from_ip": "203.0.113.10",
        "by_host": f"next{sequence}.example.test",
        "parse_confidence": 1.0,
        "is_bogon": False,
    }
    defaults.update(overrides)
    return RelayHop(**defaults)  # type: ignore[arg-type]


def test_no_hops_returns_unavailable() -> None:
    result = attribute_origin([], [], None)
    assert result.source == "unavailable"
    assert result.confidence == "unknown"
    assert "no hop" in result.reasoning.lower()


def test_all_bogon_hops_returns_unavailable() -> None:
    hops = [_hop(0, from_ip="10.0.0.5", is_bogon=True)]
    result = attribute_origin(hops, [], None)
    assert result.source == "unavailable"


def test_earliest_public_hop_selected() -> None:
    hops = [
        _hop(0, from_ip="10.0.0.5", is_bogon=True),
        _hop(1, from_ip="198.51.100.7", is_bogon=False),
        _hop(2, from_ip="198.51.100.99", is_bogon=False),
    ]
    result = attribute_origin(hops, [], None)
    assert result.origin_ip == "198.51.100.7"
    assert result.origin_hop_sequence == 1


def test_medium_confidence_without_enrichment_or_forgery() -> None:
    hops = [_hop(0, enrichment_source="unavailable")]
    result = attribute_origin(hops, [], None)
    assert result.confidence == "medium"
    assert result.source == "heuristic"


def test_high_confidence_with_enrichment_and_no_forgery() -> None:
    hops = [_hop(0, enrichment_source="geolite2-local", asn=64500, asn_org="Example ISP", country="US")]
    result = attribute_origin(hops, [], None)
    assert result.confidence == "high"
    assert result.asn_org == "Example ISP"
    assert "Example ISP" in result.reasoning


def test_forgery_signal_caps_confidence_at_low_even_with_enrichment() -> None:
    hops = [_hop(0, enrichment_source="geolite2-local", asn=64500, asn_org="Example ISP")]
    anomalies = [
        Anomaly(
            type="forged_internal_origin",
            severity="medium",
            hop_sequences=[0],
            summary="s",
            evidence="e",
        )
    ]
    result = attribute_origin(hops, anomalies, None)
    assert result.confidence == "low"
    assert "capped" in result.reasoning.lower()


def test_forgery_signal_on_later_hop_does_not_affect_earlier_candidate() -> None:
    hops = [_hop(0, enrichment_source="geolite2-local"), _hop(1)]
    anomalies = [
        Anomaly(type="forged_internal_origin", severity="medium", hop_sequences=[1], summary="s", evidence="e")
    ]
    result = attribute_origin(hops, anomalies, None)
    # candidate is hop 0; the anomaly only affects hop 1 (later), so it
    # should not cap confidence for attributing hop 0.
    assert result.origin_hop_sequence == 0
    assert result.confidence == "high"


def test_unrelated_anomaly_type_does_not_cap_confidence() -> None:
    hops = [_hop(0, enrichment_source="geolite2-local")]
    anomalies = [
        Anomaly(type="hop_count_outlier", severity="low", hop_sequences=[0], summary="s", evidence="e")
    ]
    result = attribute_origin(hops, anomalies, None)
    assert result.confidence == "high"


def test_spf_fail_mentioned_in_reasoning() -> None:
    hops = [_hop(0)]
    spf = AuthResult(mechanism="spf", result="fail", raw_segment="spf=fail")
    result = attribute_origin(hops, [], spf)
    assert "spf failed" in result.reasoning.lower()


def test_spf_pass_mentioned_in_reasoning() -> None:
    hops = [_hop(0)]
    spf = AuthResult(mechanism="spf", result="pass", raw_segment="spf=pass")
    result = attribute_origin(hops, [], spf)
    assert "spf passed" in result.reasoning.lower()


def test_spf_none_result_not_asserted_either_way() -> None:
    hops = [_hop(0)]
    spf = AuthResult(mechanism="spf", result="none", raw_segment="spf=none")
    result = attribute_origin(hops, [], spf)
    assert "spf failed" not in result.reasoning.lower()
    assert "spf passed" not in result.reasoning.lower()


def test_never_raises_on_missing_optional_hop_fields() -> None:
    hop = RelayHop(sequence=0, raw_header="x", from_ip="203.0.113.5", parse_confidence=0.0)
    result = attribute_origin([hop], [], None)
    assert result.source == "heuristic"
