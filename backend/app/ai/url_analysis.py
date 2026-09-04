"""URL extraction and analysis: IP-literal hosts, anchor-text/href
mismatches, offline redirect-parameter unwrapping, lookalike-domain checks
on link targets, and (optionally, network-gated) domain-age lookups.

Redirect unwrapping is offline-only by design: this module decodes
base64/URL-encoded destination parameters embedded in the URL itself
(a common redirector pattern -- see data/samples/17_html_redirect_chain_phishing.eml)
rather than actually following HTTP redirects, which would be a live
network call on the critical path and inconsistent with the offline-first
hard constraint. A URL that needs a live fetch to unwrap is reported as
such, not silently skipped.
"""

import base64
import ipaddress
import re
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup
from pydantic import BaseModel

from app.ai.lookalike_domain import LookalikeAnalysis, analyze_domain
from app.forensics.rdap import DomainIntel, lookup_domain_age

_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_ANCHOR_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})\b")
_REDIRECT_PARAM_NAMES = {
    "url",
    "next",
    "redirect",
    "redirect_uri",
    "target",
    "dest",
    "destination",
    "u",
    "r",
    "continue",
    "return",
    "to",
    "link",
}
NEWLY_REGISTERED_THRESHOLD_DAYS = 30


class ExtractedUrl(BaseModel):
    raw_url: str
    scheme: str | None
    host: str | None
    is_ip_literal: bool
    anchor_text: str | None = None
    anchor_claimed_domain: str | None = None
    anchor_text_mismatch: bool = False
    unwrapped_target: str | None = None
    lookalike: LookalikeAnalysis | None = None
    domain_intel: DomainIntel | None = None
    is_newly_registered: bool | None = None


class UrlAnalysis(BaseModel):
    urls: list[ExtractedUrl]


def extract_links(content: str, is_html: bool) -> list[tuple[str, str | None]]:
    """Returns (href, anchor_text) pairs. Plain-text bodies have no anchor
    text -- a bare URL is its own "anchor"."""
    if is_html:
        try:
            soup = BeautifulSoup(content, "html.parser")
            links: list[tuple[str, str | None]] = []
            for tag in soup.find_all("a", href=True):
                href_value = tag["href"]
                if not isinstance(href_value, str):
                    continue  # a list means a malformed/multi-valued href attribute
                href = href_value.strip()
                if href.lower().startswith(("http://", "https://")):
                    text = tag.get_text(strip=True) or None
                    links.append((href, text))
            # Also catch bare URLs mentioned in the visible text (outside
            # anchors), which phishing HTML bodies sometimes include too.
            for match in _URL_RE.finditer(soup.get_text(" ")):
                links.append((match.group(0), None))
            return links
        except Exception:
            pass  # fall through to plain-text extraction below
    return [(m.group(0), None) for m in _URL_RE.finditer(content)]


def analyze_urls(
    content: str,
    *,
    is_html: bool,
    trusted_brands: list[str] | None = None,
    enable_network_enrichment: bool = False,
) -> UrlAnalysis:
    results: list[ExtractedUrl] = []
    seen: set[str] = set()

    for raw_url, anchor_text in extract_links(content, is_html):
        if raw_url in seen:
            continue
        seen.add(raw_url)
        results.append(
            _analyze_one(raw_url, anchor_text, trusted_brands, enable_network_enrichment)
        )

    return UrlAnalysis(urls=results)


def _analyze_one(
    raw_url: str,
    anchor_text: str | None,
    trusted_brands: list[str] | None,
    enable_network_enrichment: bool,
) -> ExtractedUrl:
    parsed = urlparse(raw_url)
    host = parsed.hostname

    is_ip_literal = False
    if host:
        try:
            ipaddress.ip_address(host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

    anchor_claimed_domain, mismatch = _check_anchor_mismatch(anchor_text, host)
    unwrapped = _try_unwrap_redirect(raw_url)

    lookalike = None
    if host and not is_ip_literal:
        lookalike = analyze_domain(host, trusted_brands)

    domain_intel = None
    is_newly_registered = None
    if host and not is_ip_literal and enable_network_enrichment:
        domain_intel = lookup_domain_age(host, enable_network=True)
        if domain_intel.age_days is not None:
            is_newly_registered = domain_intel.age_days < NEWLY_REGISTERED_THRESHOLD_DAYS

    return ExtractedUrl(
        raw_url=raw_url,
        scheme=parsed.scheme or None,
        host=host,
        is_ip_literal=is_ip_literal,
        anchor_text=anchor_text,
        anchor_claimed_domain=anchor_claimed_domain,
        anchor_text_mismatch=mismatch,
        unwrapped_target=unwrapped,
        lookalike=lookalike,
        domain_intel=domain_intel,
        is_newly_registered=is_newly_registered,
    )


def _check_anchor_mismatch(anchor_text: str | None, actual_host: str | None) -> tuple[str | None, bool]:
    if not anchor_text or not actual_host:
        return None, False
    match = _ANCHOR_DOMAIN_RE.search(anchor_text)
    if not match:
        return None, False
    claimed = match.group(1).lower()
    actual = actual_host.lower()
    if claimed == actual or claimed == f"www.{actual}" or f"www.{claimed}" == actual:
        return claimed, False
    # Claimed domain is a suffix of the actual host (e.g. claimed
    # "paypal.com" inside a legitimate "checkout.paypal.com") -- not a
    # mismatch.
    if actual.endswith(f".{claimed}") or claimed.endswith(f".{actual}"):
        return claimed, False
    return claimed, True


def _try_unwrap_redirect(url: str) -> str | None:
    query = parse_qs(urlparse(url).query)
    for name in _REDIRECT_PARAM_NAMES:
        if name not in query or not query[name]:
            continue
        candidate = query[name][0]
        decoded = _try_decode_url_param(candidate)
        if decoded:
            return decoded
    return None


def _try_decode_url_param(value: str) -> str | None:
    # parse_qs has already percent-decoded `value`, so a URL-encoded
    # target (e.g. "http%3A%2F%2F...") arrives here as a plain URL
    # already -- check that direct case before trying base64.
    if _looks_like_url(value):
        return value

    try:
        padded = value + "=" * (-len(value) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        decoded = decoded_bytes.decode("utf-8")
        if _looks_like_url(decoded):
            return decoded
    except Exception:
        pass

    return None


def _looks_like_url(text: str) -> bool:
    return bool(re.match(r"^https?://[^\s]+\.[a-zA-Z]{2,}", text))
