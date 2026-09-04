"""Orchestrates the Phase 4 AI/content signals for one message: lookalike
sender domain, URL analysis, phishing classification, AI-text scoring.

Model-backed classifiers are expensive to construct (deserializing an ONNX
graph) so they're loaded once and cached, not per-analysis -- exactly like
the GeoIP readers in forensics/geoip.py.
"""

from email.message import EmailMessage, Message
from functools import lru_cache

from app.ai.ai_text_detection import AiTextDetector
from app.ai.lookalike_domain import analyze_domain
from app.ai.models import AiSignals
from app.ai.phishing_classifier import PhishingClassifier
from app.ai.url_analysis import analyze_urls
from app.core.config import get_settings
from app.forensics.models import ParsedEmailMeta


@lru_cache
def get_phishing_classifier() -> PhishingClassifier:
    return PhishingClassifier(get_settings().phishing_model_dir)


@lru_cache
def get_ai_text_detector() -> AiTextDetector:
    return AiTextDetector(get_settings().ai_text_model_dir)


def analyze_ai_signals(
    message: Message,
    meta: ParsedEmailMeta,
    *,
    trusted_brands: list[str] | None = None,
    enable_network_enrichment: bool = False,
) -> AiSignals:
    body_content, is_html = _extract_body(message)

    sender_lookalike = None
    if meta.from_address and "@" in meta.from_address:
        sender_domain = meta.from_address.rsplit("@", 1)[-1]
        if sender_domain:
            sender_lookalike = analyze_domain(sender_domain, trusted_brands)

    urls = analyze_urls(
        body_content,
        is_html=is_html,
        trusted_brands=trusted_brands,
        enable_network_enrichment=enable_network_enrichment,
    )

    classification_text = f"{meta.subject or ''}\n\n{body_content}"[:2000]
    phishing = get_phishing_classifier().classify(classification_text)
    ai_text = get_ai_text_detector().score(body_content[:2000])

    return AiSignals(
        sender_domain_lookalike=sender_lookalike,
        urls=urls,
        phishing=phishing,
        ai_text=ai_text,
    )


def _extract_body(message: Message) -> tuple[str, bool]:
    # get_body()/get_content() are EmailMessage-specific (the policy.default
    # parse path produces one; the compat32 fallback path in parser.py does
    # not) -- isinstance narrows the type for mypy and correctly degrades
    # to an empty body for the fallback case rather than raising.
    if not isinstance(message, EmailMessage):
        return "", False
    try:
        html_part = message.get_body(preferencelist=("html",))
        if html_part is not None:
            return str(html_part.get_content()), True
        plain_part = message.get_body(preferencelist=("plain",))
        if plain_part is not None:
            return str(plain_part.get_content()), False
    except Exception:
        pass
    return "", False
