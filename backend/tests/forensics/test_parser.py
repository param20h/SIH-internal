from app.forensics.parser import parse_email_bytes

WELL_FORMED = b"""\
From: Alice <alice@example.test>
To: bob@example.test
Subject: Hello
Date: Wed, 02 Sep 2026 09:14:00 +0000
Message-ID: <abc@example.test>

Hi Bob.
"""


def test_well_formed_email_parses_with_high_confidence() -> None:
    _message, meta = parse_email_bytes(WELL_FORMED, "test.eml")
    assert meta.from_address == "alice@example.test"
    assert meta.subject == "Hello"
    assert meta.parse_confidence == 1.0
    assert meta.issues == []
    assert meta.source_format == "eml"


def test_missing_required_headers_lowers_confidence_but_does_not_crash() -> None:
    raw = b"Subject: no from or date\n\nbody only\n"
    _message, meta = parse_email_bytes(raw, "broken.eml")
    assert meta.parse_confidence < 1.0
    assert any(issue.field == "From" for issue in meta.issues)
    assert any(issue.field == "Date" for issue in meta.issues)


def test_completely_garbage_bytes_never_raises() -> None:
    raw = bytes(range(256)) * 4
    _message, meta = parse_email_bytes(raw, "garbage.eml")
    assert meta.parse_confidence >= 0.0
    assert meta.sha256


def test_empty_bytes_never_raises() -> None:
    _message, meta = parse_email_bytes(b"", "empty.eml")
    assert meta.parse_confidence >= 0.0


def test_sha256_is_computed_over_original_bytes() -> None:
    import hashlib

    _message, meta = parse_email_bytes(WELL_FORMED, "test.eml")
    assert meta.sha256 == hashlib.sha256(WELL_FORMED).hexdigest()


def test_msg_dispatch_on_ole_magic_bytes_degrades_gracefully() -> None:
    # Not a real, complete .msg file -- just enough to hit the OLE-magic
    # dispatch path and confirm it degrades to a low-confidence result
    # instead of raising.
    raw = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    _message, meta = parse_email_bytes(raw, "broken.msg")
    assert meta.source_format == "msg"
    assert meta.parse_confidence < 1.0


def test_attachment_detection() -> None:
    raw = b"""\
From: Alice <alice@example.test>
To: bob@example.test
Subject: Invoice
Date: Wed, 02 Sep 2026 09:14:00 +0000
Message-ID: <inv@example.test>
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/plain

body

--b1
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

AAAA

--b1--
"""
    _message, meta = parse_email_bytes(raw, "invoice.eml")
    assert meta.has_attachments is True
    assert "invoice.pdf.exe" in meta.attachment_names
