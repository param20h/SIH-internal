from datetime import UTC, datetime

from app.forensics.anomalies import detect_anomalies
from app.forensics.models import RelayHop


def _hop(sequence: int, **overrides: object) -> RelayHop:
    defaults: dict[str, object] = {
        "sequence": sequence,
        "raw_header": f"hop {sequence}",
        "from_host": f"host{sequence}.example.test",
        "from_ip": "203.0.113.10",
        "by_host": f"nexthost{sequence}.example.test",
        "protocol": "ESMTP",
        "timestamp_raw": None,
        "timestamp": datetime(2026, 9, 4, 10, sequence, tzinfo=UTC),
        "parse_confidence": 1.0,
    }
    defaults.update(overrides)
    return RelayHop(**defaults)  # type: ignore[arg-type]


def test_no_anomalies_on_clean_chain() -> None:
    hop0 = _hop(0, by_host="mid.example.test", timestamp=datetime(2026, 9, 4, 10, 0, tzinfo=UTC))
    hop1 = _hop(
        1,
        from_host="mid.example.test",
        by_host="final.example.test",
        timestamp=datetime(2026, 9, 4, 10, 1, tzinfo=UTC),
    )
    anomalies = detect_anomalies([hop0, hop1])
    assert anomalies == []


def test_negative_time_delta_detected() -> None:
    hop0 = _hop(
        0,
        by_host="mid.example.test",
        timestamp=datetime(2026, 9, 4, 14, 5, tzinfo=UTC),
    )
    hop1 = _hop(
        1,
        from_host="mid.example.test",
        by_host="final.example.test",
        timestamp=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
    )
    anomalies = detect_anomalies([hop0, hop1])
    types = [a.type for a in anomalies]
    assert "negative_time_delta" in types
    hit = next(a for a in anomalies if a.type == "negative_time_delta")
    assert hit.severity == "high"
    assert hit.hop_sequences == [0, 1]


def test_bogon_ip_crossing_org_boundary_is_flagged() -> None:
    hop0 = _hop(0, from_host="mail.external-sender.test", from_ip="192.168.1.50", by_host="mid.example.test")
    hop1 = _hop(1, from_host="mid.example.test", from_ip="203.0.113.1")
    anomalies = detect_anomalies([hop0, hop1])
    bogon_hits = [a for a in anomalies if a.type == "bogon_ip_in_path"]
    assert len(bogon_hits) == 1
    assert bogon_hits[0].hop_sequences == [0]


def test_bogon_ip_within_same_org_is_not_flagged() -> None:
    # Private IPs are unremarkable on a hop that never leaves one
    # organization's own infrastructure.
    hop0 = _hop(0, from_host="relay1.example.test", from_ip="10.20.30.1", by_host="relay2.example.test")
    anomalies = detect_anomalies([hop0])
    assert not any(a.type == "bogon_ip_in_path" for a in anomalies)


def test_loopback_ip_crossing_org_boundary_detected_as_bogon() -> None:
    hop0 = _hop(0, from_host="mail.external-sender.test", from_ip="127.0.0.1", by_host="mid.example.test")
    anomalies = detect_anomalies([hop0])
    assert any(a.type == "bogon_ip_in_path" for a in anomalies)


def test_hop_count_outlier() -> None:
    hops = [_hop(i, by_host=f"h{i + 1}.example.test") for i in range(9)]
    # fix continuity so only the outlier check fires
    for i in range(len(hops) - 1):
        hops[i + 1].from_host = hops[i].by_host
    anomalies = detect_anomalies(hops)
    assert any(a.type == "hop_count_outlier" for a in anomalies)


def test_hop_count_within_threshold_not_flagged() -> None:
    hops = [_hop(i) for i in range(5)]
    for i in range(len(hops) - 1):
        hops[i + 1].from_host = hops[i].by_host
    anomalies = detect_anomalies(hops)
    assert not any(a.type == "hop_count_outlier" for a in anomalies)


def test_duplicate_by_host_detected() -> None:
    hop0 = _hop(0, by_host="mail1.example-corp.test")
    hop1 = _hop(1, from_host="mail1.example-corp.test", by_host="mail1.example-corp.test")
    hop2 = _hop(2, from_host="unknown", by_host="mail1.example-corp.test")
    anomalies = detect_anomalies([hop0, hop1, hop2])
    forged = [a for a in anomalies if a.type == "forged_internal_origin"]
    assert len(forged) >= 1
    duplicate_hit = next(a for a in forged if set(a.hop_sequences) == {0, 1, 2})
    assert duplicate_hit.severity == "medium"


def test_chain_discontinuity_detected() -> None:
    hop0 = _hop(0, by_host="mid.example.test")
    hop1 = _hop(1, from_host="totally-different-host.test")
    anomalies = detect_anomalies([hop0, hop1])
    assert any(a.type == "forged_internal_origin" for a in anomalies)


def test_future_timestamp_relative_to_wall_clock_is_not_flagged() -> None:
    # A forensic tool must be able to analyze evidence of any age; "the
    # future" is only meaningful relative to other hops in the same chain
    # (see the negative-delta test above), not to whenever the analyst
    # happens to run the tool.
    hop0 = _hop(0, timestamp=datetime(2099, 1, 1, tzinfo=UTC))
    anomalies = detect_anomalies([hop0])
    assert anomalies == []


def test_implausibly_old_timestamp_detected() -> None:
    hop0 = _hop(0, timestamp=datetime(1975, 1, 1, tzinfo=UTC))
    anomalies = detect_anomalies([hop0])
    assert any(a.type == "impossible_timestamp" for a in anomalies)


def test_missing_timestamps_are_skipped_not_crashed() -> None:
    hop0 = _hop(0, by_host="mid.example.test", timestamp=None)
    hop1 = _hop(1, from_host="mid.example.test", timestamp=None)
    assert detect_anomalies([hop0, hop1]) == []


def test_empty_chain_produces_no_anomalies() -> None:
    assert detect_anomalies([]) == []
