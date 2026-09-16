import redis
from fastapi import APIRouter
from sqlalchemy import text

from app.core.config import get_settings
from app.core.db import engine
from app.schemas.health import ComponentHealth, HealthResponse

router = APIRouter(tags=["health"])

APP_VERSION = "0.1.0"


def _check_database() -> ComponentHealth:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return ComponentHealth(name="postgres", status="ok")
    except Exception as exc:
        return ComponentHealth(name="postgres", status="unavailable", detail=str(exc))


def _check_redis() -> ComponentHealth:
    settings = get_settings()
    try:
        client = redis.from_url(settings.redis_url, socket_connect_timeout=2)
        client.ping()
        return ComponentHealth(name="redis", status="ok")
    except Exception as exc:
        return ComponentHealth(name="redis", status="unavailable", detail=str(exc))


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    components = [_check_database()]  # Removed Redis since Celery is bypassed for the demo
    overall = "ok" if all(c.status == "ok" for c in components) else "degraded"
    return HealthResponse(
        status=overall,
        app_name=settings.app_name,
        version=APP_VERSION,
        components=components,
    )
