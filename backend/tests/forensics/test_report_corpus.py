"""End-to-end forensic report generation against the full 20-file sample corpus.

Every assertion here is scoped to what Phase 1 (pure deterministic logic)
is responsible for: parsing, SPF/DKIM/DMARC extraction from
Authentication-Results, relay-chain reconstruction, and chain-level
anomaly detection. Content-based signals (homoglyph domains, URL analysis,
display-name spoofing) are explicitly out of scope until Phase 4.
"""

from pathlib import Path

import pytest

from app.forensics.report import generate_report

SAMPLES_DIR = Path(__file__).resolve().parents[3] / "data" / "samples"


def _load(name: str) -> bytes:
    return (SAMPLES_DIR / name).read_bytes()


def _report(name: str):  # type: ignore[no-untyped-def]
    return generate_report(
        _load(name),
        filename=name,
        geoip_city_db_path="/nonexistent/GeoLite2-City.mmdb",
        enable_network_enrichment=False,
    )


@pytest.mark.parametrize("name", sorted(p.name for p in SAMPLES_DIR.glob("*.eml")))
def test_every_sample_produces_a_report_without_raising(name: str) -> None:
    report = _report(name)
    assert report.filename == name
    assert report.meta.parse_confidence > 0.5
    assert report.meta.sha256


def test_01_clean_newsletter_passes_all_three() -> None:
    r = _report("01_clean_newsletter.eml")
    assert r.authentication.spf is not None and r.authentication.spf.result == "pass"
    assert r.authentication.dkim is not None and r.authentication.dkim.result == "pass"
    assert r.authentication.dmarc is not None and r.authentication.dmarc.result == "pass"
    assert not any(a.severity in ("high", "critical") for a in r.anomalies)
    assert r.risk.verdict == "clean"
    assert r.risk.score == 0
    assert r.risk.factors == []


def test_02_clean_internal_memo_passes_all_three() -> None:
    r = _report("02_clean_internal_memo.eml")
    assert r.authentication.dmarc is not None and r.authentication.dmarc.result == "pass"
    assert r.anomalies == []


def test_03_spf_fail_spoofed_bank() -> None:
    r = _report("03_spf_fail_spoofed_bank.eml")
    assert r.authentication.spf is not None and r.authentication.spf.result == "fail"
    assert r.authentication.dmarc is not None and r.authentication.dmarc.result == "fail"


def test_04_spf_softfail_marketing() -> None:
    r = _report("04_spf_softfail_marketing.eml")
    assert r.authentication.spf is not None and r.authentication.spf.result == "softfail"


def test_05_dkim_fail_invoice_scam() -> None:
    r = _report("05_dkim_fail_invoice_scam.eml")
    assert r.authentication.dkim is not None and r.authentication.dkim.result == "fail"


def test_06_dkim_missing_signature() -> None:
    r = _report("06_dkim_missing_signature.eml")
    assert r.authentication.dkim is not None and r.authentication.dkim.result == "none"
    assert r.authentication.dkim_signature_present is False
    assert r.authentication.dmarc is not None and r.authentication.dmarc.result == "fail"
    assert r.authentication.dmarc_policy == "reject"


def test_09_and_10_lookalike_domains_are_out_of_scope_for_phase1() -> None:
    # These are genuine phishing samples, but homoglyph/lookalike-domain
    # detection is a Phase 4 (content/ML) concern, not deterministic
    # relay-chain or SPF/DKIM/DMARC logic. Phase 1 should still parse them
    # cleanly and report their (in this case passing) authentication.
    for name in ("09_homoglyph_domain_paypal.eml", "10_homoglyph_domain_microsoft.eml"):
        r = _report(name)
        assert r.meta.parse_confidence > 0.5
        assert r.authentication.spf is not None


def test_11_long_relay_chain_flagged_as_outlier_not_error() -> None:
    r = _report("11_long_relay_chain_9hops.eml")
    assert r.hop_count == 9
    outliers = [a for a in r.anomalies if a.type == "hop_count_outlier"]
    assert len(outliers) == 1
    assert outliers[0].severity == "low"
    # a long chain alone should not itself be scored as high/critical
    assert not any(a.severity in ("high", "critical") for a in r.anomalies)


def test_12_relay_chain_timezone_drift_negative_delta() -> None:
    r = _report("12_relay_chain_timezone_drift.eml")
    negatives = [a for a in r.anomalies if a.type == "negative_time_delta"]
    assert len(negatives) >= 1
    assert negatives[0].severity == "high"


def test_13_forged_received_header_injected() -> None:
    r = _report("13_forged_received_header_injected.eml")
    forged = [a for a in r.anomalies if a.type == "forged_internal_origin"]
    assert len(forged) >= 1
    assert r.authentication.spf is not None and r.authentication.spf.result == "fail"


def test_14_private_ip_in_public_path() -> None:
    r = _report("14_forged_received_header_private_ip_public_path.eml")
    bogons = [a for a in r.anomalies if a.type == "bogon_ip_in_path"]
    flagged_sequences = {seq for a in bogons for seq in a.hop_sequences}
    assert len(flagged_sequences) >= 2


def test_15_and_16_base64_attachments_parse_without_crashing() -> None:
    for name in ("15_base64_payload_hidden_script.eml", "16_base64_payload_exe_attachment.eml"):
        r = _report(name)
        assert r.meta.parse_confidence > 0.5

    exe_report = _report("16_base64_payload_exe_attachment.eml")
    assert exe_report.meta.has_attachments is True
    assert any(name.endswith(".exe") for name in exe_report.meta.attachment_names)


def test_19_expired_dkim_signature() -> None:
    r = _report("19_expired_dkim_signature.eml")
    assert r.authentication.dkim_signature_present is True
    assert r.authentication.dkim_signature_expired is True
    assert any(a.type == "dkim_signature_expired" for a in r.anomalies)


def test_20_dmarc_reject_full_failure() -> None:
    r = _report("20_dmarc_fail_reject_policy.eml")
    assert r.authentication.spf is not None and r.authentication.spf.result == "fail"
    assert r.authentication.dkim is not None and r.authentication.dkim.result == "fail"
    assert r.authentication.dmarc is not None and r.authentication.dmarc.result == "fail"
    assert r.authentication.dmarc_policy == "reject"
    assert r.risk.verdict == "malicious"
    assert r.risk.score >= 50
    assert len(r.risk.factors) == 3  # spf fail, dkim fail, dmarc fail(reject)


def test_report_generation_stays_well_under_ten_seconds() -> None:
    import time

    start = time.monotonic()
    for path in sorted(SAMPLES_DIR.glob("*.eml")):
        generate_report(
            path.read_bytes(),
            filename=path.name,
            geoip_city_db_path="/nonexistent/GeoLite2-City.mmdb",
            enable_network_enrichment=False,
        )
    elapsed = time.monotonic() - start
    # 20 files combined must be nowhere near the 10s-per-email budget.
    assert elapsed < 10.0
