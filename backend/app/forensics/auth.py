"""SPF/DKIM/DMARC verdict extraction.

Real SPF and DKIM validation are protocol-level checks against DNS state at
the moment of delivery (the connecting IP for SPF, the publishing domain's
public key for DKIM). Re-deriving them offline, after the fact, from a
static file is not meaningfully possible -- and DNS state may have changed
since delivery anyway. So the authoritative source here is the
Authentication-Results header the boundary MTA already computed at delivery
time: pure header logic, zero network dependency, 100% offline-reliable,
exactly matching the hard constraint that this layer work identically with
or without connectivity. Live re-verification (Phase 4+) is additive
corroboration, not a replacement for this.
"""

import re
from datetime import UTC, datetime
from email.message import Message

from app.forensics.models import AuthenticationSummary, AuthMechanism, AuthResult, AuthResultValue

_MECHANISM_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")
_COMMENT_RE = re.compile(r"\(([^()]*)\)")
_DOMAIN_RE = re.compile(
    r"header\.from=([^\s;]+)|header\.d=([^\s;]+)|smtp\.mailfrom=(?:[^@\s;]*@)?([^\s;]+)"
)
_POLICY_RE = re.compile(r"\b(?:policy|p)=([a-zA-Z]+)")

_KNOWN_RESULTS: set[str] = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "policy",
}


def extract_authentication(message: Message, message_date: datetime | None) -> AuthenticationSummary:
    raw_headers = [str(h) for h in message.get_all("Authentication-Results", [])]
    dkim_present, dkim_expired, dkim_expiry = _inspect_dkim_signature(message, message_date)

    if not raw_headers:
        return AuthenticationSummary(
            source="unavailable",
            raw_header=None,
            dkim_signature_present=dkim_present,
            dkim_signature_expired=dkim_expired,
            dkim_expiry=dkim_expiry,
        )

    # The topmost Authentication-Results header is the one added last, i.e.
    # by the boundary MTA closest to the recipient -- the only one this
    # deployment can vouch for. Anything deeper in the chain came from a
    # relay we don't control and is not trusted for the verdict.
    authoritative = raw_headers[0]
    normalized = " ".join(authoritative.split())

    spf = dkim = dmarc = None
    dmarc_policy: str = "unknown"

    for segment in normalized.split(";"):
        segment = segment.strip()
        match = _MECHANISM_RESULT_RE.search(segment)
        if not match:
            continue
        mechanism_str, result_str = match.group(1).lower(), match.group(2).lower()
        mechanism: AuthMechanism = mechanism_str  # type: ignore[assignment]
        result = _normalize_result(result_str)
        reason = _extract_comment(segment)
        domain = _extract_domain(segment)
        auth_result = AuthResult(
            mechanism=mechanism, result=result, reason=reason, domain=domain, raw_segment=segment
        )

        if mechanism == "spf" and spf is None:
            spf = auth_result
        elif mechanism == "dkim" and dkim is None:
            dkim = auth_result
        elif mechanism == "dmarc" and dmarc is None:
            dmarc = auth_result
            policy_match = _POLICY_RE.search(segment)
            if policy_match and policy_match.group(1).lower() in ("none", "quarantine", "reject"):
                dmarc_policy = policy_match.group(1).lower()

    return AuthenticationSummary(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        source="authentication-results-header",
        raw_header=authoritative,
        dkim_signature_present=dkim_present,
        dkim_signature_expired=dkim_expired,
        dkim_expiry=dkim_expiry,
        dmarc_policy=dmarc_policy,
    )


def _normalize_result(word: str) -> AuthResultValue:
    if word in _KNOWN_RESULTS:
        return word  # type: ignore[return-value]
    return "unknown"


def _extract_comment(segment: str) -> str | None:
    match = _COMMENT_RE.search(segment)
    return match.group(1).strip() if match else None


def _extract_domain(segment: str) -> str | None:
    match = _DOMAIN_RE.search(segment)
    if not match:
        return None
    return next((g for g in match.groups() if g), None)


def _inspect_dkim_signature(
    message: Message, message_date: datetime | None
) -> tuple[bool, bool, datetime | None]:
    raw_sig = message.get("DKIM-Signature")
    if not raw_sig:
        return False, False, None

    tags = _parse_dkim_tags(str(raw_sig))
    expiry_raw = tags.get("x")
    if expiry_raw is None or not expiry_raw.isdigit():
        return True, False, None

    expiry = datetime.fromtimestamp(int(expiry_raw), tz=UTC)
    reference = message_date if message_date is not None else datetime.now(tz=UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=UTC)
    expired = expiry < reference
    return True, expired, expiry


def _parse_dkim_tags(raw_sig: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in raw_sig.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags
