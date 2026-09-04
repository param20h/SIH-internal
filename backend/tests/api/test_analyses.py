from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings

SAMPLES_DIR = Path(__file__).resolve().parents[3] / "data" / "samples"


def _sample_bytes(name: str) -> bytes:
    return (SAMPLES_DIR / name).read_bytes()


class _FakeTask:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def delay(self, analysis_id: str) -> None:
        self.calls.append(analysis_id)


@pytest.fixture
def fake_celery_task(monkeypatch: pytest.MonkeyPatch) -> _FakeTask:
    fake = _FakeTask()
    monkeypatch.setattr("app.api.analyses.analyze_email_task", fake)
    return fake


def test_upload_single_email_runs_synchronously(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyses",
        files={"file": ("03.eml", _sample_bytes("03_spf_fail_spoofed_bank.eml"), "message/rfc822")},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "complete"
    assert body["authentication"]["spf"]["result"] == "fail"
    assert body["hop_count"] == len(body["hops"])


def test_upload_empty_file_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyses", files={"file": ("empty.eml", b"", "message/rfc822")}
    )
    assert response.status_code == 400


def test_upload_oversized_file_rejected(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.analyses.get_settings", lambda: _tiny_limit_settings())
    response = client.post(
        "/api/v1/analyses",
        files={"file": ("big.eml", _sample_bytes("01_clean_newsletter.eml"), "message/rfc822")},
    )
    assert response.status_code == 413


def _tiny_limit_settings() -> Settings:
    settings = get_settings()
    return settings.model_copy(update={"upload_max_bytes": 10})


def test_get_analysis_by_id(client: TestClient) -> None:
    upload = client.post(
        "/api/v1/analyses",
        files={"file": ("13.eml", _sample_bytes("13_forged_received_header_injected.eml"), "message/rfc822")},
    )
    analysis_id = upload.json()["id"]

    response = client.get(f"/api/v1/analyses/{analysis_id}")
    assert response.status_code == 200
    assert response.json()["id"] == analysis_id
    assert len(response.json()["anomalies"]) >= 1


def test_get_analysis_not_found(client: TestClient) -> None:
    response = client.get("/api/v1/analyses/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


def test_list_analyses(client: TestClient) -> None:
    client.post(
        "/api/v1/analyses",
        files={"file": ("01.eml", _sample_bytes("01_clean_newsletter.eml"), "message/rfc822")},
    )
    client.post(
        "/api/v1/analyses",
        files={"file": ("03.eml", _sample_bytes("03_spf_fail_spoofed_bank.eml"), "message/rfc822")},
    )

    response = client.get("/api/v1/analyses", params={"limit": 10})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 2
    assert len(body["items"]) >= 2


def test_list_analyses_filter_by_spf(client: TestClient) -> None:
    client.post(
        "/api/v1/analyses",
        files={"file": ("03.eml", _sample_bytes("03_spf_fail_spoofed_bank.eml"), "message/rfc822")},
    )
    response = client.get("/api/v1/analyses", params={"spf_result": "fail"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert all(item["spf_result"] == "fail" for item in body["items"])


def test_export_json(client: TestClient) -> None:
    upload = client.post(
        "/api/v1/analyses",
        files={"file": ("20.eml", _sample_bytes("20_dmarc_fail_reject_policy.eml"), "message/rfc822")},
    )
    analysis_id = upload.json()["id"]

    response = client.get(f"/api/v1/analyses/{analysis_id}/export", params={"format": "json"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert payload["authentication"]["dmarc"]["result"] == "fail"


def test_export_txt(client: TestClient) -> None:
    upload = client.post(
        "/api/v1/analyses",
        files={"file": ("12.eml", _sample_bytes("12_relay_chain_timezone_drift.eml"), "message/rfc822")},
    )
    analysis_id = upload.json()["id"]

    response = client.get(f"/api/v1/analyses/{analysis_id}/export", params={"format": "txt"})
    assert response.status_code == 200
    assert "TVA FORENSIC REPORT" in response.text
    assert "negative_time_delta" in response.text


def test_export_eml_returns_original_bytes(client: TestClient) -> None:
    original = _sample_bytes("13_forged_received_header_injected.eml")
    upload = client.post(
        "/api/v1/analyses", files={"file": ("13.eml", original, "message/rfc822")}
    )
    analysis_id = upload.json()["id"]

    response = client.get(f"/api/v1/analyses/{analysis_id}/export", params={"format": "eml"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "message/rfc822"
    assert response.content == original


def test_export_eml_available_even_when_pending(
    client: TestClient, fake_celery_task: _FakeTask
) -> None:
    batch = client.post(
        "/api/v1/analyses/batch",
        files=[("files", ("01.eml", _sample_bytes("01_clean_newsletter.eml"), "message/rfc822"))],
    )
    analysis_id = batch.json()["items"][0]["analysis_id"]

    response = client.get(f"/api/v1/analyses/{analysis_id}/export", params={"format": "eml"})
    assert response.status_code == 200

    # But json/txt require the analysis to actually be complete.
    response = client.get(f"/api/v1/analyses/{analysis_id}/export", params={"format": "json"})
    assert response.status_code == 409


def test_export_not_found(client: TestClient) -> None:
    response = client.get(
        "/api/v1/analyses/00000000-0000-0000-0000-000000000000/export", params={"format": "json"}
    )
    assert response.status_code == 404


def test_batch_upload_queues_celery_task(client: TestClient, fake_celery_task: _FakeTask) -> None:
    response = client.post(
        "/api/v1/analyses/batch",
        files=[
            ("files", ("01.eml", _sample_bytes("01_clean_newsletter.eml"), "message/rfc822")),
            ("files", ("03.eml", _sample_bytes("03_spf_fail_spoofed_bank.eml"), "message/rfc822")),
        ],
    )
    assert response.status_code == 202
    body = response.json()
    assert len(body["items"]) == 2
    assert all(item["status"] == "pending" for item in body["items"])
    assert len(fake_celery_task.calls) == 2


def test_batch_upload_skips_invalid_files(client: TestClient, fake_celery_task: _FakeTask) -> None:
    response = client.post(
        "/api/v1/analyses/batch",
        files=[
            ("files", ("empty.eml", b"", "message/rfc822")),
            ("files", ("ok.eml", _sample_bytes("02_clean_internal_memo.eml"), "message/rfc822")),
        ],
    )
    assert response.status_code == 202
    body = response.json()
    assert len(body["items"]) == 1
    assert len(body["skipped"]) == 1
    assert body["skipped"][0]["filename"] == "empty.eml"
