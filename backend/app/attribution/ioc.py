"""Indicator-of-compromise extraction from a completed ForensicReport.

Extracts everything with forensic value -- IPs, domains, URLs, attachment
hashes, sender addresses -- and keeps the context each one was found in,
because an unlabeled list of IPs and domains is far less useful to an
analyst than one that says *why* each entry is here. Deliberately does not
try to filter out the recipient's own mail infrastructure (there's no
reliable, generic way to know which hostnames are "ours" without an
org-specific config this project doesn't have) -- every hop's hostnames
and IPs are included, with context that lets a human judge relevance.
"""

from typing import Literal

from pydantic import BaseModel

from app.forensics.models import ForensicReport

IocType = Literal["ipv4", "ipv6", "domain", "url", "sha256", "email"]


class Ioc(BaseModel):
    type: IocType
    value: str
    context: str


def extract_iocs(report: ForensicReport) -> list[Ioc]:
    iocs: list[Ioc] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc_type: IocType, value: str | None, context: str) -> None:
        if not value:
            return
        key = (ioc_type, value)
        if key in seen:
            return
        seen.add(key)
        iocs.append(Ioc(type=ioc_type, value=value, context=context))

    if report.meta.from_address:
        add("email", report.meta.from_address, "sender (From) address")

    for hop in report.hops:
        if hop.from_ip:
            add(
                _ip_type(hop.from_ip),
                hop.from_ip,
                f"relay hop #{hop.sequence} source IP (claimed host: {hop.from_host or 'unknown'})",
            )
        if hop.from_host:
            add("domain", hop.from_host, f"relay hop #{hop.sequence} source hostname")
        if hop.by_host:
            add("domain", hop.by_host, f"relay hop #{hop.sequence} receiving hostname")

    for attachment in report.meta.attachments:
        add(
            "sha256",
            attachment.sha256,
            f"attachment {attachment.filename!r} ({attachment.size_bytes} bytes, {attachment.content_type or 'unknown type'})",
        )

    for url in report.ai_signals.urls.urls:
        add("url", url.raw_url, "link found in message body")
        if url.host:
            if url.is_ip_literal:
                add(_ip_type(url.host), url.host, f"IP-literal link host ({url.raw_url})")
            else:
                add("domain", url.host, f"host of link {url.raw_url}")
        if url.unwrapped_target:
            add("url", url.unwrapped_target, f"unwrapped redirect target of {url.raw_url}")

    return iocs


def _ip_type(ip: str) -> Literal["ipv4", "ipv6"]:
    return "ipv6" if ":" in ip else "ipv4"
