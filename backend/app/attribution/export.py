"""STIX 2.1 and CSV export for extracted IOCs.

STIX 2.1 (https://docs.oasis-open.org/cti/stix/v2.1/) is hand-built here
rather than via the `stix2` library: the format needed is a handful of
`indicator` SDOs in a `bundle`, which is a small, well-specified JSON
shape -- pulling in a full STIX object-modeling library for that is more
dependency than the task warrants. Every object still follows the spec
precisely (id format `<type>--<uuid>`, RFC 3339 timestamps, valid STIX
patterning language per type).
"""

import csv
import io
import uuid
from datetime import UTC, datetime

from app.attribution.ioc import Ioc, IocType

_PATTERN_BUILDERS: dict[IocType, str] = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ipv6": "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "email": "[email-addr:value = '{value}']",
}


def _stix_pattern(ioc: Ioc) -> str:
    escaped = ioc.value.replace("\\", "\\\\").replace("'", "\\'")
    return _PATTERN_BUILDERS[ioc.type].format(value=escaped)


def _rfc3339_now() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def build_stix_bundle(iocs: list[Ioc], case_id: str) -> dict[str, object]:
    timestamp = _rfc3339_now()
    objects: list[dict[str, object]] = []
    for ioc in iocs:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": timestamp,
                "modified": timestamp,
                "name": f"{ioc.type}: {ioc.value}",
                "description": f"[{case_id}] {ioc.context}",
                "indicator_types": ["malicious-activity"],
                "pattern": _stix_pattern(ioc),
                "pattern_type": "stix",
                "valid_from": timestamp,
            }
        )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def build_csv(iocs: list[Ioc]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "value", "context"])
    for ioc in iocs:
        writer.writerow([ioc.type, ioc.value, ioc.context])
    return output.getvalue()
