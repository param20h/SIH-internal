from app.forensics.models import Anomaly, AuthenticationSummary, AuthResult
from app.scoring.engine import compute_risk_score


def _auth(**overrides: object) -> AuthenticationSummary:
    defaults: dict[str, object] = {"source": "authentication-results-header"}
    defaults.update(overrides)
    return AuthenticationSummary(**defaults)  # type: ignore[arg-type]


def test_clean_authentication_scores_zero() -> None:
    auth = _auth(
        spf=AuthResult(mechanism="spf", result="pass", raw_segment="spf=pass"),
        dkim=AuthResult(mechanism="dkim", result="pass", raw_segment="dkim=pass"),
        dmarc=AuthResult(mechanism="dmarc", result="pass", raw_segment="dmarc=pass"),
    )
    risk = compute_risk_score(auth, [])
    assert risk.score == 0
    assert risk.verdict == "clean"
    assert risk.factors == []


def test_every_factor_carries_its_own_evidence() -> None:
    auth = _auth(
        spf=AuthResult(mechanism="spf", result="fail", raw_segment="spf=fail (evidence-x)"),
    )
    risk = compute_risk_score(auth, [])
    assert len(risk.factors) == 1
    factor = risk.factors[0]
    assert factor.weight > 0
    assert "evidence-x" in factor.evidence
    assert factor.category == "authentication"


def test_dmarc_fail_weight_scales_with_policy() -> None:
    reject = _auth(
        dmarc=AuthResult(mechanism="dmarc", result="fail", raw_segment="x"), dmarc_policy="reject"
    )
    none_policy = _auth(
        dmarc=AuthResult(mechanism="dmarc", result="fail", raw_segment="x"), dmarc_policy="none"
    )
    reject_score = compute_risk_score(reject, [])
    none_score = compute_risk_score(none_policy, [])
    assert reject_score.score > none_score.score


def test_dmarc_pass_contributes_nothing() -> None:
    auth = _auth(dmarc=AuthResult(mechanism="dmarc", result="pass", raw_segment="x"))
    risk = compute_risk_score(auth, [])
    assert risk.score == 0


def test_anomaly_severity_feeds_score() -> None:
    auth = _auth()
    anomalies = [
        Anomaly(type="bogon_ip_in_path", severity="high", hop_sequences=[0], summary="s", evidence="e")
    ]
    risk = compute_risk_score(auth, anomalies)
    assert risk.score > 0
    assert any(f.category == "relay_chain" for f in risk.factors)


def test_info_severity_anomaly_does_not_inflate_score() -> None:
    auth = _auth()
    anomalies = [Anomaly(type="hop_count_outlier", severity="info", hop_sequences=[], summary="s", evidence="e")]
    risk = compute_risk_score(auth, anomalies)
    assert risk.score == 0
    assert risk.factors == []


def test_score_is_clamped_to_100() -> None:
    auth = _auth(
        spf=AuthResult(mechanism="spf", result="fail", raw_segment="x"),
        dkim=AuthResult(mechanism="dkim", result="fail", raw_segment="x"),
        dmarc=AuthResult(mechanism="dmarc", result="fail", raw_segment="x"),
        dmarc_policy="reject",
    )
    anomalies = [
        Anomaly(type="bogon_ip_in_path", severity="critical", hop_sequences=[i], summary=f"s{i}", evidence="e")
        for i in range(10)
    ]
    risk = compute_risk_score(auth, anomalies)
    assert risk.score == 100
    assert risk.verdict == "malicious"


def test_verdict_thresholds() -> None:
    clean = compute_risk_score(_auth(), [])
    assert clean.verdict == "clean"

    suspicious_auth = _auth(
        dmarc=AuthResult(mechanism="dmarc", result="fail", raw_segment="x"), dmarc_policy="quarantine"
    )
    suspicious_anomalies = [
        Anomaly(type="hop_count_outlier", severity="medium", hop_sequences=[], summary="s", evidence="e")
    ]
    suspicious = compute_risk_score(suspicious_auth, suspicious_anomalies)
    assert 30 <= suspicious.score < 70
    assert suspicious.verdict == "suspicious"


def test_factors_sorted_by_weight_descending() -> None:
    auth = _auth(
        spf=AuthResult(mechanism="spf", result="softfail", raw_segment="x"),
        dmarc=AuthResult(mechanism="dmarc", result="fail", raw_segment="x"),
        dmarc_policy="reject",
    )
    risk = compute_risk_score(auth, [])
    weights = [f.weight for f in risk.factors]
    assert weights == sorted(weights, reverse=True)


def test_expired_dkim_is_not_double_counted() -> None:
    """dkim_signature_expired is scored once, as the medium-severity
    Anomaly generate_report() creates for it -- not again as a separate
    authentication factor. See weights.yaml for the full rationale."""
    auth = _auth(dkim_signature_expired=True)
    anomaly = Anomaly(
        type="dkim_signature_expired",
        severity="medium",
        hop_sequences=[],
        summary="DKIM signature is expired",
        evidence="e",
    )
    risk = compute_risk_score(auth, [anomaly])
    assert len(risk.factors) == 1
    assert risk.score == 10  # exactly the "medium" severity weight, once
