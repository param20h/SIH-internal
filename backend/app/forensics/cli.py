"""CLI entrypoint: print a full forensic report for any .eml/.msg file.

    python -m app.forensics.cli data/samples/03_spf_fail_spoofed_bank.eml
    python -m app.forensics.cli --json path/to/file.eml
    python -m app.forensics.cli --online path/to/file.eml   # allow live RDAP
"""

import argparse
import sys
from pathlib import Path

from app.forensics.render import render_text_report
from app.forensics.report import generate_report

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
        print(render_text_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
