from pathlib import Path

from fastapi.testclient import TestClient

SAMPLES_DIR = Path(__file__).resolve().parents[3] / "data" / "samples"


def _sample_bytes(name: str) -> bytes:
    return (SAMPLES_DIR / name).read_bytes()


def test_stats_empty_database(client: TestClient) -> None:
    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    body = response.json()
    assert body["total_analyses"] == 0
    assert body["status_breakdown"] == {}


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
