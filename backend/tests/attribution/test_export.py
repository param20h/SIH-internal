import json

from app.attribution.export import build_csv, build_stix_bundle
from app.attribution.ioc import Ioc


def test_stix_bundle_structure() -> None:
    iocs = [
        Ioc(type="ipv4", value="203.0.113.5", context="test"),
        Ioc(type="domain", value="evil.test", context="test"),
        Ioc(type="sha256", value="a" * 64, context="test"),
    ]
    bundle = build_stix_bundle(iocs, case_id="CASE-1")
    assert bundle["type"] == "bundle"
    assert str(bundle["id"]).startswith("bundle--")
    objects = bundle["objects"]
    assert isinstance(objects, list)
    assert len(objects) == 3
    for obj in objects:
        assert obj["type"] == "indicator"
        assert obj["spec_version"] == "2.1"
        assert str(obj["id"]).startswith("indicator--")
        assert obj["pattern_type"] == "stix"
        assert "CASE-1" in obj["description"]


def test_stix_patterns_per_type() -> None:
    iocs = [
        Ioc(type="ipv4", value="203.0.113.5", context="c"),
        Ioc(type="ipv6", value="2001:db8::1", context="c"),
        Ioc(type="domain", value="evil.test", context="c"),
        Ioc(type="url", value="http://evil.test/x", context="c"),
        Ioc(type="sha256", value="a" * 64, context="c"),
        Ioc(type="email", value="a@evil.test", context="c"),
    ]
    bundle = build_stix_bundle(iocs, case_id="CASE-1")
    patterns = [obj["pattern"] for obj in bundle["objects"]]
    assert "[ipv4-addr:value = '203.0.113.5']" in patterns
    assert "[ipv6-addr:value = '2001:db8::1']" in patterns
    assert "[domain-name:value = 'evil.test']" in patterns
    assert "[url:value = 'http://evil.test/x']" in patterns
    assert f"[file:hashes.'SHA-256' = '{'a' * 64}']" in patterns
    assert "[email-addr:value = 'a@evil.test']" in patterns


def test_stix_bundle_is_json_serializable() -> None:
    iocs = [Ioc(type="domain", value="evil.test", context="c")]
    bundle = build_stix_bundle(iocs, case_id="CASE-1")
    serialized = json.dumps(bundle)
    reloaded = json.loads(serialized)
    assert reloaded["type"] == "bundle"


def test_stix_pattern_escapes_single_quotes() -> None:
    iocs = [Ioc(type="url", value="http://evil.test/x?q=o'brien", context="c")]
    bundle = build_stix_bundle(iocs, case_id="CASE-1")
    pattern = bundle["objects"][0]["pattern"]  # type: ignore[index]
    assert "\\'brien" in pattern


def test_empty_iocs_produces_empty_bundle() -> None:
    bundle = build_stix_bundle([], case_id="CASE-1")
    assert bundle["objects"] == []


def test_csv_has_header_and_rows() -> None:
    iocs = [
        Ioc(type="ipv4", value="203.0.113.5", context="hop 0"),
        Ioc(type="domain", value="evil.test", context="sender"),
    ]
    csv_text = build_csv(iocs)
    lines = csv_text.strip().splitlines()
    assert lines[0] == "type,value,context"
    assert len(lines) == 3
    assert "203.0.113.5" in lines[1]


def test_csv_handles_commas_in_context_via_quoting() -> None:
    iocs = [Ioc(type="domain", value="evil.test", context="context, with a comma")]
    csv_text = build_csv(iocs)
    assert '"context, with a comma"' in csv_text


def test_empty_iocs_produces_header_only_csv() -> None:
    csv_text = build_csv([])
    assert csv_text.strip() == "type,value,context"
