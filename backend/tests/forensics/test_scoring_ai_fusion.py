"""Tests for Phase 4 AI-signal fusion into the risk score (compute_risk_score
with an AiSignals argument). test_scoring.py covers the Phase 1-3
deterministic-only path; this file covers the additive layer on top."""

from app.ai.ai_text_detection import AiTextScore
from app.ai.lookalike_domain import LookalikeAnalysis, LookalikeMatch
from app.ai.models import AiSignals
from app.ai.phishing_classifier import PhishingClassification
from app.ai.url_analysis import ExtractedUrl, UrlAnalysis
from app.forensics.models import AuthenticationSummary
from app.scoring.engine import compute_risk_score

_CLEAN_AUTH = AuthenticationSummary(source="authentication-results-header")
_EMPTY_URLS = UrlAnalysis(urls=[])
_UNAVAILABLE_PHISHING = PhishingClassification(source="unavailable")
_UNAVAILABLE_AI_TEXT = AiTextScore(source="unavailable")


def _signals(**overrides: object) -> AiSignals:
    defaults: dict[str, object] = {
        "sender_domain_lookalike": None,
        "urls": _EMPTY_URLS,
        "phishing": _UNAVAILABLE_PHISHING,
        "ai_text": _UNAVAILABLE_AI_TEXT,
    }
    defaults.update(overrides)
    return AiSignals(**defaults)  # type: ignore[arg-type]


def test_no_ai_signals_argument_is_backward_compatible() -> None:
    # Phase 1-3 callers that don't pass ai_signals must still work.
    risk = compute_risk_score(_CLEAN_AUTH, [])
    assert risk.score == 0


def test_all_unavailable_ai_signals_contribute_nothing() -> None:
    risk = compute_risk_score(_CLEAN_AUTH, [], _signals())
    assert risk.score == 0
    assert risk.factors == []


def test_phishing_classifier_above_threshold_scored() -> None:
    signals = _signals(
        phishing=PhishingClassification(source="onnx-model", phishing_probability=0.9, label="phishing")
    )
    risk = compute_risk_score(_CLEAN_AUTH, [], signals)
    assert risk.score > 0
    assert any(f.category == "phishing_classifier" for f in risk.factors)


def test_phishing_classifier_below_threshold_not_scored() -> None:
    signals = _signals(
        phishing=PhishingClassification(source="onnx-model", phishing_probability=0.2, label="ham")
    )
    risk = compute_risk_score(_CLEAN_AUTH, [], signals)
    assert risk.score == 0


def test_sender_lookalike_scored_higher_than_url_lookalike() -> None:
    lookalike = LookalikeAnalysis(
        domain="paypaI.com",
        is_punycode=False,
        matches=[
            LookalikeMatch(matched_brand="paypal.com", method="levenshtein", detail="1 edit away")
        ],
    )
    sender_risk = compute_risk_score(_CLEAN_AUTH, [], _signals(sender_domain_lookalike=lookalike))

    url = ExtractedUrl(
        raw_url="https://paypaI.com/x",
        scheme="https",
        host="paypaI.com",
        is_ip_literal=False,
        lookalike=lookalike,
    )
    url_risk = compute_risk_score(_CLEAN_AUTH, [], _signals(urls=UrlAnalysis(urls=[url])))

    assert sender_risk.score > url_risk.score


def test_punycode_adds_bonus_only_when_already_a_lookalike_match() -> None:
    lookalike_with_match = LookalikeAnalysis(
        domain="xn--pple-43d.com",
        is_punycode=True,
        decoded_unicode="аpple.com",
        matches=[
            LookalikeMatch(matched_brand="apple.com", method="homoglyph_skeleton", detail="exact skeleton")
        ],
    )
    risk = compute_risk_score(_CLEAN_AUTH, [], _signals(sender_domain_lookalike=lookalike_with_match))
    assert any("punycode" in f.name.lower() for f in risk.factors)

    # Punycode alone, with no brand match, should not add the bonus --
    # legitimate internationalized domains exist and aren't inherently
    # suspicious without a brand-impersonation signal too.
    lookalike_no_match = LookalikeAnalysis(
        domain="xn--something-legit.com", is_punycode=True, decoded_unicode="somethinglegit.com", matches=[]
    )
    risk2 = compute_risk_score(_CLEAN_AUTH, [], _signals(sender_domain_lookalike=lookalike_no_match))
    assert risk2.score == 0


def test_ip_literal_url_scored() -> None:
    url = ExtractedUrl(raw_url="http://1.2.3.4/x", scheme="http", host="1.2.3.4", is_ip_literal=True)
    risk = compute_risk_score(_CLEAN_AUTH, [], _signals(urls=UrlAnalysis(urls=[url])))
    assert any(f.category == "url_analysis" for f in risk.factors)


def test_anchor_text_mismatch_scored() -> None:
    url = ExtractedUrl(
        raw_url="https://evil.test/x",
        scheme="https",
        host="evil.test",
        is_ip_literal=False,
        anchor_text="paypal.com",
        anchor_claimed_domain="paypal.com",
        anchor_text_mismatch=True,
    )
    risk = compute_risk_score(_CLEAN_AUTH, [], _signals(urls=UrlAnalysis(urls=[url])))
    assert any("different domain" in f.name for f in risk.factors)


def test_low_perplexity_flag_scored_low_weight() -> None:
    signals = _signals(ai_text=AiTextScore(source="onnx-model", perplexity=10.0, low_perplexity_flag=True))
    risk = compute_risk_score(_CLEAN_AUTH, [], signals)
    ai_text_factors = [f for f in risk.factors if f.category == "ai_text"]
    assert len(ai_text_factors) == 1
    # Deliberately the smallest weight in the whole config -- see
    # weights.yaml and ai_text_detection.py for why.
    assert ai_text_factors[0].weight <= 10


def test_ai_text_without_flag_not_scored() -> None:
    signals = _signals(ai_text=AiTextScore(source="onnx-model", perplexity=80.0, low_perplexity_flag=False))
    risk = compute_risk_score(_CLEAN_AUTH, [], signals)
    assert not any(f.category == "ai_text" for f in risk.factors)


def test_multiple_ai_signals_combine_additively() -> None:
    lookalike = LookalikeAnalysis(
        domain="paypaI.com",
        is_punycode=False,
        matches=[LookalikeMatch(matched_brand="paypal.com", method="levenshtein", detail="1 edit away")],
    )
    signals = _signals(
        sender_domain_lookalike=lookalike,
        phishing=PhishingClassification(source="onnx-model", phishing_probability=0.95, label="phishing"),
    )
    risk = compute_risk_score(_CLEAN_AUTH, [], signals)
    categories = {f.category for f in risk.factors}
    assert "lookalike_domain" in categories
    assert "phishing_classifier" in categories
