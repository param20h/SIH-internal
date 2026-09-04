from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage

from app.forensics.auth import extract_authentication


def _message_with_headers(**headers: str) -> EmailMessage:
    message = EmailMessage(policy=policy.default)
    for key, value in headers.items():
        header_name = key.replace("_", "-")
        message[header_name] = value
    return message


def test_no_authentication_results_header_is_unavailable() -> None:
    message = _message_with_headers(From="a@example.test")
    summary = extract_authentication(message, None)
    assert summary.source == "unavailable"
    assert summary.spf is None


def test_spf_fail_is_extracted_with_reason() -> None:
    message = _message_with_headers(
        Authentication_Results=(
            "mail1.example-corp.test; "
            "spf=fail (domain does not designate 1.2.3.4 as permitted sender) "
            "smtp.mailfrom=alerts@firstnational.test; "
            "dkim=none (message not signed); "
            "dmarc=fail (policy=reject) header.from=firstnational.test"
        )
    )
    summary = extract_authentication(message, None)
    assert summary.source == "authentication-results-header"
    assert summary.spf is not None
    assert summary.spf.result == "fail"
    assert "1.2.3.4" in (summary.spf.reason or "")
    assert summary.dkim is not None
    assert summary.dkim.result == "none"
    assert summary.dmarc is not None
    assert summary.dmarc.result == "fail"
    assert summary.dmarc_policy == "reject"


def test_all_pass() -> None:
    message = _message_with_headers(
        Authentication_Results=(
            "mail1.example-corp.test; "
            "spf=pass smtp.mailfrom=news@example-press.test; "
            "dkim=pass header.d=example-press.test; "
            "dmarc=pass (policy=quarantine) header.from=example-press.test"
        )
    )
    summary = extract_authentication(message, None)
    assert summary.spf is not None and summary.spf.result == "pass"
    assert summary.dkim is not None and summary.dkim.result == "pass"
    assert summary.dmarc is not None and summary.dmarc.result == "pass"
    assert summary.dmarc_policy == "quarantine"


def test_only_topmost_authentication_results_header_is_authoritative() -> None:
    message = EmailMessage(policy=policy.default)
    # On a real parsed message, get_all("Authentication-Results") returns
    # headers in raw top-to-bottom file order -- and because each hop
    # prepends its own headers, index 0 is always the one added last, by
    # the boundary MTA closest to the recipient. We only need to confirm
    # extract_authentication trusts index 0, regardless of which value
    # that happens to be.
    message["Authentication-Results"] = "mail1.example-corp.test; spf=fail"
    message["Authentication-Results"] = "some-relay.test; spf=pass"
    headers = message.get_all("Authentication-Results")
    assert headers is not None and len(headers) == 2
    summary = extract_authentication(message, None)
    assert summary.raw_header == headers[0]


def test_dkim_signature_expired_relative_to_message_date() -> None:
    message = _message_with_headers(
        DKIM_Signature="v=1; a=rsa-sha256; d=example.test; s=sel; t=1704067200; x=1706745600;"
    )
    message_date = datetime(2026, 9, 14, tzinfo=UTC)
    summary = extract_authentication(message, message_date)
    assert summary.dkim_signature_present is True
    assert summary.dkim_signature_expired is True
    assert summary.dkim_expiry is not None
    assert summary.dkim_expiry.year == 2024


def test_dkim_signature_not_expired() -> None:
    message = _message_with_headers(
        DKIM_Signature="v=1; a=rsa-sha256; d=example.test; s=sel; t=1704067200; x=9999999999;"
    )
    message_date = datetime(2026, 9, 14, tzinfo=UTC)
    summary = extract_authentication(message, message_date)
    assert summary.dkim_signature_present is True
    assert summary.dkim_signature_expired is False


def test_no_dkim_signature_header() -> None:
    message = _message_with_headers(From="a@example.test")
    summary = extract_authentication(message, None)
    assert summary.dkim_signature_present is False
    assert summary.dkim_signature_expired is False
