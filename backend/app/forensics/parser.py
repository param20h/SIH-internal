"""Robust .eml/.msg parsing.

This module must never raise on malformed or malicious input. Every failure
mode degrades to a lower parse_confidence score plus a recorded ParseIssue
instead of propagating an exception -- the rest of the pipeline (and the
API layer above it) can then treat "some fields are missing" as a normal,
expected outcome rather than a crash to recover from.
"""

import contextlib
import hashlib
from datetime import datetime
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Literal

from app.forensics.models import AttachmentInfo, ParsedEmailMeta, ParseIssue

REQUIRED_HEADERS = ("From", "Date", "Subject", "Message-ID")
DEFECT_PENALTY = 0.05
MISSING_HEADER_PENALTY = 0.12


def parse_email_bytes(raw: bytes, filename: str) -> tuple[Message, ParsedEmailMeta]:
    """Parse raw email bytes into a stdlib Message plus our normalized metadata.

    Dispatches to the .msg (Outlook) parser when the filename or magic bytes
    indicate an OLE compound file; otherwise treats the input as RFC 5322
    (.eml). Always returns a usable result -- worst case, an empty Message
    and a ParsedEmailMeta with parse_confidence 0.0 and issues explaining why.
    """
    sha256 = hashlib.sha256(raw).hexdigest()
    is_msg = filename.lower().endswith(".msg") or raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    if is_msg:
        return _parse_msg(raw, sha256)
    return _parse_eml(raw, sha256)


def _parse_eml(raw: bytes, sha256: str) -> tuple[Message, ParsedEmailMeta]:
    issues: list[ParseIssue] = []
    message: Message
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        issues.append(ParseIssue(field="__root__", detail=f"parser raised {exc!r}, falling back"))
        try:
            message = BytesParser(policy=policy.compat32).parsebytes(raw)
        except Exception as exc2:
            empty = EmailMessage()
            issues.append(ParseIssue(field="__root__", detail=f"fallback parser raised {exc2!r}"))
            return empty, _build_meta(empty, issues, sha256, "eml")

    for defect in getattr(message, "defects", []):
        issues.append(ParseIssue(field="__message__", detail=str(defect)))

    return message, _build_meta(message, issues, sha256, "eml")


def _parse_msg(raw: bytes, sha256: str) -> tuple[Message, ParsedEmailMeta]:
    import io

    issues: list[ParseIssue] = []
    empty = EmailMessage()

    try:
        import extract_msg
    except ImportError:
        issues.append(ParseIssue(field="__root__", detail="extract_msg not installed"))
        return empty, _build_meta(empty, issues, sha256, "msg")

    try:
        msg_obj: Any = extract_msg.openMsg(io.BytesIO(raw))
    except Exception as exc:
        issues.append(ParseIssue(field="__root__", detail=f".msg parser raised {exc!r}"))
        return empty, _build_meta(empty, issues, sha256, "msg")

    try:
        message = EmailMessage(policy=policy.default)
        message["From"] = msg_obj.sender or ""
        message["To"] = msg_obj.to or ""
        message["Subject"] = msg_obj.subject or ""
        message["Date"] = msg_obj.date or ""
        message["Message-ID"] = getattr(msg_obj, "messageId", "") or ""
        raw_headers = getattr(msg_obj, "header", None)
        if raw_headers is not None:
            for line in str(raw_headers).splitlines():
                if line.lower().startswith("received:"):
                    message["Received"] = line.split(":", 1)[1].strip()
                if line.lower().startswith("authentication-results:"):
                    message["Authentication-Results"] = line.split(":", 1)[1].strip()
        message.set_content(msg_obj.body or "")
    except Exception as exc:
        issues.append(ParseIssue(field="__root__", detail=f".msg field extraction raised {exc!r}"))
        return empty, _build_meta(empty, issues, sha256, "msg")
    finally:
        with contextlib.suppress(Exception):
            msg_obj.close()

    return message, _build_meta(message, issues, sha256, "msg")


def _build_meta(
    message: Message,
    issues: list[ParseIssue],
    sha256: str,
    source_format: Literal["eml", "msg"],
) -> ParsedEmailMeta:
    issues = list(issues)

    for header in REQUIRED_HEADERS:
        if not message.get(header):
            issues.append(ParseIssue(field=header, detail="required header missing"))

    from_display_name, from_address = _split_from(message)
    to_addresses = _extract_to_addresses(message)
    date_raw = message.get("Date")
    date_parsed = _safe_parse_date(date_raw, issues)

    content_type = None
    has_attachments = False
    attachment_names: list[str] = []
    attachments: list[AttachmentInfo] = []
    try:
        content_type = message.get_content_type()
        if message.is_multipart():
            for part in message.walk():
                filename = part.get_filename()
                disposition = str(part.get("Content-Disposition", ""))
                if filename or "attachment" in disposition.lower():
                    has_attachments = True
                    display_name = filename or "(unnamed attachment)"
                    attachment_names.append(display_name)
                    attachments.append(_hash_attachment(part, display_name, issues))
    except Exception as exc:
        issues.append(ParseIssue(field="body", detail=f"failed walking MIME parts: {exc!r}"))

    penalty = DEFECT_PENALTY * sum(1 for i in issues if i.field == "__message__")
    penalty += MISSING_HEADER_PENALTY * sum(1 for h in REQUIRED_HEADERS if not message.get(h))
    penalty += 0.3 if not message.get("From") and not message.get("Received") else 0.0
    confidence = max(0.0, min(1.0, 1.0 - penalty))

    return ParsedEmailMeta(
        from_display_name=from_display_name,
        from_address=from_address,
        to_addresses=to_addresses,
        subject=_safe_str(message.get("Subject")),
        date_raw=date_raw,
        date_parsed=date_parsed,
        message_id=_safe_str(message.get("Message-ID")),
        return_path=_safe_str(message.get("Return-Path")),
        content_type=content_type,
        has_attachments=has_attachments,
        attachment_names=attachment_names,
        attachments=attachments,
        parse_confidence=confidence,
        issues=issues,
        source_format=source_format,
        sha256=sha256,
    )


def _hash_attachment(part: Message, display_name: str, issues: list[ParseIssue]) -> AttachmentInfo:
    """SHA256 of an attachment's decoded bytes -- a forensic IOC, not just
    display metadata. Never raises: an attachment that can't be decoded
    (corrupt encoding, unsupported transfer encoding) still gets an
    AttachmentInfo entry, just with a zero-length hash and a recorded issue,
    rather than silently disappearing from the report."""
    try:
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            payload = b""
        digest = hashlib.sha256(payload).hexdigest()
        return AttachmentInfo(
            filename=display_name,
            content_type=part.get_content_type(),
            size_bytes=len(payload),
            sha256=digest,
        )
    except Exception as exc:
        issues.append(ParseIssue(field="attachments", detail=f"failed hashing {display_name!r}: {exc!r}"))
        return AttachmentInfo(
            filename=display_name, content_type=None, size_bytes=0, sha256=hashlib.sha256(b"").hexdigest()
        )


def _split_from(message: Message) -> tuple[str | None, str | None]:
    raw_from = message.get("From")
    if not raw_from:
        return None, None
    try:
        parsed = getaddresses([str(raw_from)])
        if parsed:
            name, addr = parsed[0]
            return (name or None), (addr or None)
    except Exception:
        pass
    return None, str(raw_from)


def _extract_to_addresses(message: Message) -> list[str]:
    raw_to = message.get_all("To", [])
    try:
        return [addr for _name, addr in getaddresses([str(h) for h in raw_to]) if addr]
    except Exception:
        return []


def _safe_parse_date(date_raw: str | None, issues: list[ParseIssue]) -> datetime | None:
    if not date_raw:
        return None
    try:
        return parsedate_to_datetime(date_raw)
    except Exception as exc:
        issues.append(ParseIssue(field="Date", detail=f"could not parse date: {exc!r}"))
        return None


def _safe_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)
