"""Received-header parsing and relay-chain reconstruction.

Received headers are prepended by each hop, so the raw header order on the
wire is newest-first (closest to the recipient at the top, origin at the
bottom). Real-world Received headers are also notoriously inconsistent
between MTA implementations, so every extraction here is best-effort and
never raises -- a hop we can only partially parse is still worth reporting,
just with a lower per-hop confidence score.
"""

import ipaddress
import re
from datetime import datetime
from email.message import Message
from email.utils import parsedate_to_datetime

from app.forensics.models import RelayHop

_FROM_RE = re.compile(r"\bfrom\s+([^\s(;]+)(?:\s*\(([^)]*)\))?", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s(;]+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+([^\s;]+)", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_CANDIDATE_RE = re.compile(r"\b[0-9a-fA-F:]{2,45}\b")


def parse_relay_chain(message: Message) -> list[RelayHop]:
    """Return hops ordered earliest-to-latest (origin first, recipient last)."""
    raw_headers = [str(h) for h in message.get_all("Received", [])]
    ordered_raw = list(reversed(raw_headers))
    return [_parse_single_hop(sequence, raw) for sequence, raw in enumerate(ordered_raw)]


def _parse_single_hop(sequence: int, raw: str) -> RelayHop:
    normalized = " ".join(raw.split())

    from_host: str | None = None
    from_ip: str | None = None
    found = 0

    from_match = _FROM_RE.search(normalized)
    if from_match:
        from_host = from_match.group(1).rstrip(",;")
        found += 1
        paren = from_match.group(2) or ""
        from_ip = _extract_ip(paren) or _extract_ip(from_match.group(0))

    by_match = _BY_RE.search(normalized)
    by_host = None
    if by_match:
        by_host = by_match.group(1).rstrip(",;")
        found += 1

    with_match = _WITH_RE.search(normalized)
    protocol = with_match.group(1).rstrip(",;") if with_match else None

    timestamp_raw, timestamp = _extract_timestamp(normalized)
    if timestamp is not None:
        found += 1

    return RelayHop(
        sequence=sequence,
        raw_header=raw,
        from_host=from_host,
        from_ip=from_ip,
        by_host=by_host,
        protocol=protocol,
        timestamp_raw=timestamp_raw,
        timestamp=timestamp,
        parse_confidence=round(found / 3.0, 2),
    )


def _extract_ip(text: str) -> str | None:
    for match in _IPV4_RE.finditer(text):
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    for match in _IPV6_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        if ":" not in candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


def _extract_timestamp(normalized: str) -> tuple[str | None, datetime | None]:
    if ";" not in normalized:
        return None, None
    timestamp_raw = normalized.rsplit(";", 1)[1].strip()
    if not timestamp_raw:
        return None, None
    try:
        return timestamp_raw, parsedate_to_datetime(timestamp_raw)
    except (TypeError, ValueError):
        return timestamp_raw, None
