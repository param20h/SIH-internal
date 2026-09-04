"""Explainable weighted risk scoring.

Hard constraint this module exists to satisfy: no black-box score. Every
point added to the total is tied to a named ScoreFactor with its weight
and the raw evidence that triggered it -- the API and UI never have to
show a number without justification.
"""

from pathlib import Path
from typing import Any

import yaml

from app.forensics.models import Anomaly, AuthenticationSummary, RiskScore, ScoreFactor, Verdict

_WEIGHTS_PATH = Path(__file__).parent / "weights.yaml"


def _load_weights() -> dict[str, Any]:
    with _WEIGHTS_PATH.open() as f:
        loaded: dict[str, Any] = yaml.safe_load(f)
    return loaded


_WEIGHTS = _load_weights()


def compute_risk_score(authentication: AuthenticationSummary, anomalies: list[Anomaly]) -> RiskScore:
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

    total = sum(f.weight for f in factors)
    score = max(0, min(100, total))
    verdict = _verdict_for(score)
    factors.sort(key=lambda f: f.weight, reverse=True)

    return RiskScore(score=score, verdict=verdict, factors=factors)


def _verdict_for(score: int) -> Verdict:
    thresholds = _WEIGHTS["verdict_thresholds"]
    if score >= thresholds["malicious"]:
        return "malicious"
    if score >= thresholds["suspicious"]:
        return "suspicious"
    return "clean"
