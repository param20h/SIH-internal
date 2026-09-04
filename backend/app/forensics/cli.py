"""CLI entrypoint: print a full forensic report for any .eml/.msg file.

    python -m app.forensics.cli data/samples/03_spf_fail_spoofed_bank.eml
    python -m app.forensics.cli --json path/to/file.eml
    python -m app.forensics.cli --online path/to/file.eml   # allow live RDAP
"""

import argparse
import sys
from pathlib import Path

from app.forensics.models import ForensicReport
from app.forensics.report import generate_report

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_DEFAULT_GEOIP_CITY = "/data/geoip/GeoLite2-City.mmdb"
_DEFAULT_GEOIP_ASN = "/data/geoip/GeoLite2-ASN.mmdb"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TVA deterministic forensics CLI")
    parser.add_argument("path", type=Path, help="Path to a .eml or .msg file")
    parser.add_argument("--json", action="store_true", help="Print the raw JSON report instead")
    parser.add_argument(
        "--online", action="store_true", help="Allow live RDAP domain-age lookup (network required)"
    )
    parser.add_argument("--geoip-city", default=_DEFAULT_GEOIP_CITY, help="Path to GeoLite2-City.mmdb")
    parser.add_argument("--geoip-asn", default=_DEFAULT_GEOIP_ASN, help="Path to GeoLite2-ASN.mmdb")
    args = parser.parse_args(argv)

    if not args.path.exists():
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 1

    raw = args.path.read_bytes()
    report = generate_report(
        raw,
        filename=args.path.name,
        geoip_city_db_path=args.geoip_city,
        geoip_asn_db_path=args.geoip_asn,
        enable_network_enrichment=args.online,
    )

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        _print_human_readable(report)
    return 0


def _print_human_readable(report: ForensicReport) -> None:
    m = report.meta
    a = report.authentication

    _section("TVA FORENSIC REPORT")
    print(f"file:              {report.filename}")
    print(f"sha256:            {m.sha256}")
    print(f"parse confidence:  {m.parse_confidence:.0%}")
    if m.issues:
        print(f"parse issues:      {len(m.issues)}")
        for issue in m.issues:
            print(f"  - [{issue.field}] {issue.detail}")

    _section("MESSAGE")
    print(f"from:        {m.from_display_name or ''} <{m.from_address or 'unknown'}>")
    print(f"to:          {', '.join(m.to_addresses) or 'unknown'}")
    print(f"subject:     {m.subject or ''}")
    print(f"date:        {m.date_raw or 'unknown'}")
    print(f"message-id:  {m.message_id or 'unknown'}")
    print(f"attachments: {', '.join(m.attachment_names) if m.has_attachments else 'none'}")

    _section("AUTHENTICATION (SPF / DKIM / DMARC)")
    if a.source == "unavailable":
        print("no Authentication-Results header present -- unable to determine SPF/DKIM/DMARC")
    else:
        for label, result in (("SPF", a.spf), ("DKIM", a.dkim), ("DMARC", a.dmarc)):
            if result is None:
                print(f"{label:6s} unknown (not reported by boundary MTA)")
            else:
                reason = f" -- {result.reason}" if result.reason else ""
                print(f"{label:6s} {result.result.upper()}{reason}")
        print(f"dmarc policy published: {a.dmarc_policy}")
    if a.dkim_signature_present:
        expired = "EXPIRED" if a.dkim_signature_expired else "not expired"
        print(f"dkim signature:    present, {expired}")

    _section(f"RELAY CHAIN ({report.hop_count} hops, earliest -> latest)")
    if not report.hops:
        print("no Received headers found")
    for hop in report.hops:
        geo = ""
        if hop.enrichment_source == "geolite2-local":
            geo = f"  [{hop.city or '?'}, {hop.country or '?'} | AS{hop.asn or '?'} {hop.asn_org or ''}]"
        bogon = "  [BOGON]" if hop.is_bogon else ""
        ts = hop.timestamp.isoformat() if hop.timestamp else (hop.timestamp_raw or "unknown")
        print(
            f"  #{hop.sequence}  from={hop.from_host or '?'} ({hop.from_ip or 'no-ip'})  "
            f"by={hop.by_host or '?'}  with={hop.protocol or '?'}  at={ts}"
            f"  conf={hop.parse_confidence:.0%}{geo}{bogon}"
        )

    _section(f"ANOMALIES ({len(report.anomalies)})")
    if not report.anomalies:
        print("none detected")
    for anomaly in sorted(report.anomalies, key=lambda a: _SEVERITY_ORDER.get(a.severity, 9)):
        print(f"  [{anomaly.severity.upper():8s}] {anomaly.type}: {anomaly.summary}")
        print(f"             evidence: {anomaly.evidence}")

    if report.sender_domain_intel:
        _section("SENDER DOMAIN INTEL")
        di = report.sender_domain_intel
        if di.source == "unavailable":
            print(f"domain: {di.domain}  age: unavailable ({di.detail or 'no data'})")
        else:
            badge = "[cached]" if di.source == "cached" else "[live]"
            print(f"domain: {di.domain}  age: {di.age_days} days {badge}")

    print()


def _section(title: str) -> None:
    print(f"\n== {title} " + "=" * max(0, 70 - len(title)))


if __name__ == "__main__":
    raise SystemExit(main())
