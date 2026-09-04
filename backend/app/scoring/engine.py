"""Explainable weighted risk scoring.

Hard constraint this module exists to satisfy: no black-box score. Every
point added to the total is tied to a named ScoreFactor with its weight
and the raw evidence that triggered it -- the API and UI never have to
show a number without justification.
"""

from pathlib import Path
from typing import Any

import yaml

from app.ai.lookalike_domain import LookalikeAnalysis
from app.ai.models import AiSignals
from app.forensics.models import Anomaly, AuthenticationSummary, RiskScore, ScoreFactor, Verdict

_WEIGHTS_PATH = Path(__file__).parent / "weights.yaml"


def _load_weights() -> dict[str, Any]:
    with _WEIGHTS_PATH.open() as f:
        loaded: dict[str, Any] = yaml.safe_load(f)
    return loaded


_WEIGHTS = _load_weights()


def compute_risk_score(
    authentication: AuthenticationSummary,
    anomalies: list[Anomaly],
    ai_signals: AiSignals | None = None,
) -> RiskScore:
    factors: list[ScoreFactor] = []
    auth_weights = _WEIGHTS["authentication"]

    if authentication.spf is not None:
        weight = auth_weights["spf"].get(authentication.spf.result, 0)
        if weight:
            factors.append(
                ScoreFactor(
                    name=f"SPF {authentication.spf.result}",
                    weight=weight,
                    evidence=authentication.spf.raw_segment,
                    category="authentication",
                )
            )

    if authentication.dkim is not None:
        weight = auth_weights["dkim"].get(authentication.dkim.result, 0)
        if weight:
            factors.append(
                ScoreFactor(
                    name=f"DKIM {authentication.dkim.result}",
                    weight=weight,
                    evidence=authentication.dkim.raw_segment,
                    category="authentication",
                )
            )

    if authentication.dmarc is not None and authentication.dmarc.result == "fail":
        by_policy = auth_weights["dmarc"]["fail_by_policy"]
        weight = by_policy.get(authentication.dmarc_policy, by_policy["unknown"])
        factors.append(
            ScoreFactor(
                name=f"DMARC fail (policy={authentication.dmarc_policy})",
                weight=weight,
                evidence=authentication.dmarc.raw_segment,
                category="authentication",
            )
        )

    # An expired DKIM signature is not scored here -- generate_report()
    # already turns it into a "medium" severity Anomaly, scored below via
    # anomaly_severity. See weights.yaml for the full explanation.

    severity_weights = _WEIGHTS["anomaly_severity"]
    for anomaly in anomalies:
        weight = severity_weights.get(anomaly.severity, 0)
        if weight:
            factors.append(
                ScoreFactor(
                    name=anomaly.summary, weight=weight, evidence=anomaly.evidence, category="relay_chain"
                )
            )

    if ai_signals is not None:
        factors.extend(_score_ai_signals(ai_signals))

    total = sum(f.weight for f in factors)
    score = max(0, min(100, total))
    verdict = _verdict_for(score)
    factors.sort(key=lambda f: f.weight, reverse=True)

    return RiskScore(score=score, verdict=verdict, factors=factors)


def _score_ai_signals(ai_signals: AiSignals) -> list[ScoreFactor]:
    factors: list[ScoreFactor] = []

    phishing = ai_signals.phishing
    phishing_weights = _WEIGHTS["phishing_classifier"]
    if (
        phishing.source == "onnx-model"
        and phishing.phishing_probability is not None
        and phishing.phishing_probability >= phishing_weights["probability_threshold"]
    ):
        factors.append(
            ScoreFactor(
                name="Phishing classifier flagged this message",
                weight=phishing_weights["weight"],
                evidence=f"model-estimated phishing probability {phishing.phishing_probability:.0%}",
                category="phishing_classifier",
            )
        )

    lookalike_weights = _WEIGHTS["lookalike_domain"]
    if ai_signals.sender_domain_lookalike is not None:
        factors.extend(
            _score_lookalike(
                ai_signals.sender_domain_lookalike, lookalike_weights["sender_domain"], "sender address"
            )
        )

    url_weights = _WEIGHTS["url_analysis"]
    for url in ai_signals.urls.urls:
        if url.is_ip_literal:
            factors.append(
                ScoreFactor(
                    name="Link uses a bare IP address instead of a domain",
                    weight=url_weights["ip_literal"],
                    evidence=url.raw_url,
                    category="url_analysis",
                )
            )
        if url.anchor_text_mismatch:
            factors.append(
                ScoreFactor(
                    name="Link text claims a different domain than its destination",
                    weight=url_weights["anchor_text_mismatch"],
                    evidence=(
                        f"anchor text claims {url.anchor_claimed_domain!r}, "
                        f"actual destination is {url.host!r} ({url.raw_url})"
                    ),
                    category="url_analysis",
                )
            )
        if url.is_newly_registered:
            factors.append(
                ScoreFactor(
                    name="Link points to a newly registered domain",
                    weight=url_weights["newly_registered_domain"],
                    evidence=(
                        f"{url.host} registered "
                        f"{url.domain_intel.age_days if url.domain_intel else '?'} days ago"
                    ),
                    category="url_analysis",
                )
            )
        if url.lookalike is not None:
            factors.extend(_score_lookalike(url.lookalike, lookalike_weights["url"], f"link to {url.host}"))

    ai_text = ai_signals.ai_text
    if ai_text.source == "onnx-model" and ai_text.low_perplexity_flag:
        factors.append(
            ScoreFactor(
                name="Email body reads as unusually predictable to a reference language model",
                weight=_WEIGHTS["ai_text"]["low_perplexity_flag"],
                evidence=(
                    f"perplexity {ai_text.perplexity:.1f} -- a weak, informational signal only, "
                    "not a confident AI-generated-text classification"
                ),
                category="ai_text",
            )
        )

    return factors


def _score_lookalike(
    lookalike: LookalikeAnalysis, method_weights: dict[str, int], context: str
) -> list[ScoreFactor]:
    factors: list[ScoreFactor] = []
    for match in lookalike.matches:
        weight = method_weights.get(match.method, 0)
        if not weight:
            continue
        factors.append(
            ScoreFactor(
                name=f"{context.capitalize()} looks like {match.matched_brand}",
                weight=weight,
                evidence=match.detail,
                category="lookalike_domain",
            )
        )
    if lookalike.matches and lookalike.is_punycode:
        factors.append(
            ScoreFactor(
                name=f"{context.capitalize()} uses punycode/IDN encoding",
                weight=_WEIGHTS["lookalike_domain"]["punycode_bonus"],
                evidence=f"{lookalike.domain} decodes to {lookalike.decoded_unicode!r}",
                category="lookalike_domain",
            )
        )
    return factors


def _verdict_for(score: int) -> Verdict:
    thresholds = _WEIGHTS["verdict_thresholds"]
    if score >= thresholds["malicious"]:
        return "malicious"
    if score >= thresholds["suspicious"]:
        return "suspicious"
    return "clean"
