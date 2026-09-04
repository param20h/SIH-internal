from app.forensics.geoip import enrich_hops
from app.forensics.models import RelayHop


def _hop(from_ip: str | None) -> RelayHop:
    return RelayHop(sequence=0, raw_header="x", from_ip=from_ip, parse_confidence=1.0)


def test_missing_db_file_degrades_gracefully() -> None:
    hops = [_hop("203.0.113.5")]
    result = enrich_hops(hops, city_db_path="/nonexistent/GeoLite2-City.mmdb")
    assert result[0].enrichment_source == "unavailable"
    assert result[0].country is None


def test_hop_without_ip_is_left_untouched() -> None:
    hops = [_hop(None)]
    result = enrich_hops(hops, city_db_path="/nonexistent/GeoLite2-City.mmdb")
    assert result[0].enrichment_source == "unavailable"


def test_bogon_ip_marked_without_needing_a_database() -> None:
    hops = [_hop("192.168.1.1")]
    result = enrich_hops(hops, city_db_path="/nonexistent/GeoLite2-City.mmdb")
    assert result[0].is_bogon is True
    assert result[0].enrichment_source == "unavailable"


def test_never_raises_on_bad_db_path() -> None:
    hops = [_hop("203.0.113.5")]
    # Should not raise even with a path that isn't a valid mmdb at all.
    enrich_hops(hops, city_db_path="/etc/hosts", asn_db_path="/etc/hosts")
