from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_200() -> None:
    response = client.get("/health")
    assert response.status_code == 200


def test_health_response_shape() -> None:
    response = client.get("/health")
    body = response.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["app_name"] == "TVA - Threat Variance Authority"
    component_names = {c["name"] for c in body["components"]}
    assert component_names == {"postgres", "redis"}
    for component in body["components"]:
        assert component["status"] in {"ok", "degraded", "unavailable"}


def test_health_never_raises_on_unreachable_dependencies() -> None:
    # Dependencies may be unreachable when running tests outside docker compose;
    # the endpoint must degrade gracefully rather than 500.
    response = client.get("/health")
    assert response.status_code == 200
