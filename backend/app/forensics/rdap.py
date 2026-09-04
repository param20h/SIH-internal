"""RDAP domain-registration lookup, strictly opt-in and always degrading gracefully.

RDAP (RFC 7482) is the modern, structured successor to WHOIS and needs no
API key -- but it is still a live network call, which the platform's hard
offline requirement does not allow to be on the critical path. Callers must
explicitly pass enable_network=True to attempt a live lookup; the default
is to only ever consult the in-process cache and report "unavailable"
otherwise. A cache hit is always labeled "cached" in the result so the UI
can show the visible badge the constraint requires.
"""

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime

from app.forensics.models import DomainIntel

_RDAP_TIMEOUT_SECONDS = 2.5
_RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"

# Process-lifetime cache. A durable, shared cache (Redis/Postgres) belongs
# in Phase 2's persistence layer; this is enough to make repeated lookups
# within one CLI run or one worker process free and offline.
_CACHE: dict[str, DomainIntel] = {}


def lookup_domain_age(domain: str, *, enable_network: bool = False) -> DomainIntel:
    domain = domain.lower().strip().rstrip(".")

    cached = _CACHE.get(domain)
    if cached is not None:
        return DomainIntel(
            domain=domain,
            registration_date=cached.registration_date,
            age_days=cached.age_days,
            source="cached",
            detail=cached.detail,
        )

    if not enable_network:
        return DomainIntel(domain=domain, source="unavailable", detail="network enrichment disabled")

    result = _fetch_live(domain)
    if result.source == "live":
        _CACHE[domain] = result
    return result


def _fetch_live(domain: str) -> DomainIntel:
    url = _RDAP_ENDPOINT.format(domain=domain)
    try:
        request = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(request, timeout=_RDAP_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return DomainIntel(domain=domain, source="unavailable", detail=f"RDAP lookup failed: {exc}")

    registration_date = _extract_registration_date(payload)
    age_days = None
    if registration_date is not None:
        age_days = (datetime.now(tz=UTC) - registration_date).days

    return DomainIntel(
        domain=domain,
        registration_date=registration_date,
        age_days=age_days,
        source="live",
        detail=None if registration_date else "RDAP response had no registration event",
    )


def _extract_registration_date(payload: dict[str, object]) -> datetime | None:
    events = payload.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") != "registration":
            continue
        raw_date = event.get("eventDate")
        if not isinstance(raw_date, str):
            continue
        try:
            return datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
