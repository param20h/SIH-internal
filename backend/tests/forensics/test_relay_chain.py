from email import policy
from email.message import Message
from email.parser import BytesParser

from app.forensics.relay_chain import parse_relay_chain

HOP_A = (
    "from mx1.example-corp.test (mx1.example-corp.test [203.0.113.5])\n"
    "\tby mail1.example-corp.test (Postfix) with ESMTPS id 1XyZ\n"
    "\tfor <a@example-corp.test>; Wed, 02 Sep 2026 09:15:00 +0000 (UTC)"
)
HOP_B = (
    "from submit.example-press.test (submit.example-press.test [198.51.100.20])\n"
    "\tby mx1.example-corp.test (Postfix) with ESMTP id 2AbC\n"
    "\tfor <a@example-corp.test>; Wed, 02 Sep 2026 09:14:18 +0000 (UTC)"
)


def _message_with_received(*headers_newest_first: str) -> Message:
    # Build via raw-bytes parsing (like the real production path in
    # parser.py) rather than EmailMessage.__setitem__, since the default
    # policy rejects header values containing literal embedded newlines
    # when set programmatically -- real folded headers only unfold
    # correctly when they come from the parser.
    raw = "".join(f"Received: {header}\n" for header in headers_newest_first)
    raw += "\n"
    return BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8"))


def test_no_received_headers_returns_empty_list() -> None:
    message = _message_with_received()
    assert parse_relay_chain(message) == []


def test_hops_are_reversed_to_earliest_first() -> None:
    message = _message_with_received(HOP_A, HOP_B)
    hops = parse_relay_chain(message)
    assert len(hops) == 2
    # HOP_B (submit -> mx1) happened first chronologically and in the chain,
    # so it must be sequence 0 after reversal even though it appears second
    # in the raw (newest-first) header order.
    assert hops[0].from_host == "submit.example-press.test"
    assert hops[1].from_host == "mx1.example-corp.test"


def test_hop_fields_extracted() -> None:
    message = _message_with_received(HOP_A)
    hop = parse_relay_chain(message)[0]
    assert hop.from_host == "mx1.example-corp.test"
    assert hop.from_ip == "203.0.113.5"
    assert hop.by_host == "mail1.example-corp.test"
    assert hop.protocol == "ESMTPS"
    assert hop.timestamp is not None
    assert hop.timestamp.year == 2026
    assert hop.parse_confidence == 1.0


def test_malformed_received_header_never_raises() -> None:
    message = _message_with_received("this is not a valid received header at all")
    hops = parse_relay_chain(message)
    assert len(hops) == 1
    assert hops[0].parse_confidence < 1.0


def test_ipv6_address_extracted() -> None:
    header = (
        "from mail.example.test (mail.example.test [2001:db8::1])\n"
        "\tby mx.example-corp.test with ESMTP id 3DeF; Wed, 02 Sep 2026 09:00:00 +0000"
    )
    hop = parse_relay_chain(_message_with_received(header))[0]
    assert hop.from_ip == "2001:db8::1"
