from pathlib import Path

from fastapi.testclient import TestClient

SAMPLES_DIR = Path(__file__).resolve().parents[3] / "data" / "samples"


def _sample_bytes(name: str) -> bytes:
    return (SAMPLES_DIR / name).read_bytes()


def test_stats_response_shape_and_invariants(client: TestClient) -> None:
    # Deliberately does not assert an empty database: tests run against
    # the real dev Postgres instance (see conftest.py), so other rows may
    # already exist from manual use of the running stack. Only structural
    # invariants that must hold regardless of existing data are checked
    # here; test_stats_reflects_uploaded_analyses below checks the
    # this-test's-own-data case with >= assertions instead of ==.
    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    body = response.json()

    assert body["total_analyses"] >= 0
    assert sum(body["status_breakdown"].values()) == body["total_analyses"]
    assert body["analyses_last_24h"] <= body["total_analyses"]
    for breakdown in (
        body["status_breakdown"],
        body["spf_breakdown"],
        body["dkim_breakdown"],
        body["dmarc_breakdown"],
        body["anomaly_type_breakdown"],
        body["anomaly_severity_breakdown"],
    ):
        assert all(isinstance(v, int) and v >= 0 for v in breakdown.values())


def test_stats_reflects_uploaded_analyses(client: TestClient) -> None:
    client.post(
        "/api/v1/analyses",
        files={"file": ("03.eml", _sample_bytes("03_spf_fail_spoofed_bank.eml"), "message/rfc822")},
    )
    client.post(
        "/api/v1/analyses",
        files={"file": ("01.eml", _sample_bytes("01_clean_newsletter.eml"), "message/rfc822")},
    )

    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    body = response.json()
    assert body["total_analyses"] >= 2
    assert body["status_breakdown"].get("complete", 0) >= 2
    assert body["spf_breakdown"].get("fail", 0) >= 1
    assert body["spf_breakdown"].get("pass", 0) >= 1
    assert body["analyses_last_24h"] >= 2


def test_stats_anomaly_breakdown(client: TestClient) -> None:
    client.post(
        "/api/v1/analyses",
        files={
            "file": (
                "14.eml",
                _sample_bytes("14_forged_received_header_private_ip_public_path.eml"),
                "message/rfc822",
            )
        },
    )
    response = client.get("/api/v1/stats")
    body = response.json()
    assert body["anomaly_type_breakdown"].get("bogon_ip_in_path", 0) >= 1
    assert body["anomaly_severity_breakdown"].get("high", 0) >= 1
