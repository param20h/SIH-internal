"""Local GeoLite2 hop enrichment.

Reads .mmdb files from disk only -- no network calls. When the database
file is missing (the common case until someone drops a licensed MaxMind
download into data/geoip/, see data/geoip/README.md), every lookup simply
returns None and the hop's enrichment_source stays "unavailable". The
relay-chain reconstruction and anomaly detection never depend on this
succeeding.
"""

import contextlib
from dataclasses import dataclass

from app.forensics.ip_utils import is_bogon
from app.forensics.models import RelayHop


@dataclass
class _CityHit:
    country: str | None
    city: str | None
    latitude: float | None
    longitude: float | None


@dataclass
class _AsnHit:
    asn: int | None
    org: str | None


class GeoIPEnricher:
    """Wraps geoip2 Readers for the City and (optional) ASN databases.

    Both readers are opened lazily and independently; either or both being
    absent is a normal, expected state, not an error.
    """

    def __init__(self, city_db_path: str, asn_db_path: str | None = None) -> None:
        self._city_reader = self._open_reader(city_db_path)
        self._asn_reader = self._open_reader(asn_db_path) if asn_db_path else None

    @staticmethod
    def _open_reader(path: str | None) -> object | None:
        if not path:
            return None
        try:
            import geoip2.database

            return geoip2.database.Reader(path)
        except Exception:
            return None

    def _city(self, ip: str) -> _CityHit | None:
        if self._city_reader is None:
            return None
        try:
            resp = self._city_reader.city(ip)  # type: ignore[attr-defined]
            return _CityHit(
                country=resp.country.iso_code,
                city=resp.city.name,
                latitude=resp.location.latitude,
                longitude=resp.location.longitude,
            )
        except Exception:
            return None

    def _asn(self, ip: str) -> _AsnHit | None:
        if self._asn_reader is None:
            return None
        try:
            resp = self._asn_reader.asn(ip)  # type: ignore[attr-defined]
            return _AsnHit(
                asn=resp.autonomous_system_number,
                org=resp.autonomous_system_organization,
            )
        except Exception:
            return None

    def enrich(self, hop: RelayHop) -> RelayHop:
        if not hop.from_ip:
            return hop

        hop.is_bogon = is_bogon(hop.from_ip)
        if hop.is_bogon:
            return hop

        city = self._city(hop.from_ip)
        asn = self._asn(hop.from_ip)
        if city is None and asn is None:
            return hop

        if city:
            hop.country = city.country
            hop.city = city.city
            hop.latitude = city.latitude
            hop.longitude = city.longitude
        if asn:
            hop.asn = asn.asn
            hop.asn_org = asn.org
        hop.enrichment_source = "geolite2-local"
        return hop

    def close(self) -> None:
        for reader in (self._city_reader, self._asn_reader):
            if reader is not None:
                with contextlib.suppress(Exception):
                    reader.close()  # type: ignore[attr-defined]


def enrich_hops(hops: list[RelayHop], city_db_path: str, asn_db_path: str | None = None) -> list[RelayHop]:
    enricher = GeoIPEnricher(city_db_path, asn_db_path)
    try:
        return [enricher.enrich(hop) for hop in hops]
    finally:
        enricher.close()
