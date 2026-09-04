from pathlib import Path

from app.attribution.ioc import extract_iocs
from app.forensics.report import generate_report

SAMPLES_DIR = Path(__file__).resolve().parents[3] / "data" / "samples"


def _report(name: str):  # type: ignore[no-untyped-def]
    raw = (SAMPLES_DIR / name).read_bytes()
    return generate_report(raw, filename=name, geoip_city_db_path="/nonexistent.mmdb")


def test_sender_email_extracted() -> None:
    report = _report("03_spf_fail_spoofed_bank.eml")
    iocs = extract_iocs(report)
    emails = [i for i in iocs if i.type == "email"]
    assert any(i.value == "alerts@firstnational.test" for i in emails)


def test_hop_ips_and_hostnames_extracted() -> None:
    report = _report("13_forged_received_header_injected.eml")
    iocs = extract_iocs(report)
    ips = {i.value for i in iocs if i.type in ("ipv4", "ipv6")}
    assert "193.106.30.44" in ips
    domains = {i.value for i in iocs if i.type == "domain"}
    assert "mail1.example-corp.test" in domains


def test_attachment_sha256_extracted() -> None:
    report = _report("16_base64_payload_exe_attachment.eml")
    iocs = extract_iocs(report)
    hashes = [i for i in iocs if i.type == "sha256"]
    assert len(hashes) == 1
    assert len(hashes[0].value) == 64  # sha256 hex digest length
    assert "Invoice_40188.pdf.exe" in hashes[0].context


def test_urls_and_link_hosts_extracted() -> None:
    report = _report("17_html_redirect_chain_phishing.eml")
    iocs = extract_iocs(report)
    urls = {i.value for i in iocs if i.type == "url"}
    assert any("track.redirectify.test" in u for u in urls)
    # the unwrapped redirect target should also be present as its own IOC
    assert any("login-securedocview.ich" in u for u in urls)


def test_ip_literal_url_host_extracted_as_ip() -> None:
    report = _report("18_html_redirect_chain_shortener.eml")
    iocs = extract_iocs(report)
    ips = {i.value for i in iocs if i.type == "ipv4"}
    assert "185.220.101.9" in ips


def test_no_duplicate_iocs() -> None:
    report = _report("20_dmarc_fail_reject_policy.eml")
    iocs = extract_iocs(report)
    keys = [(i.type, i.value) for i in iocs]
    assert len(keys) == len(set(keys))


def test_clean_sample_still_yields_some_iocs() -> None:
    # Even a clean message has IOC-shaped facts worth recording (sender
    # address, relay hostnames) -- IOC extraction isn't verdict-gated.
    report = _report("01_clean_newsletter.eml")
    iocs = extract_iocs(report)
    assert len(iocs) > 0
    assert any(i.type == "email" for i in iocs)
