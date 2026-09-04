from typing import Literal

from pydantic import BaseModel

ComponentStatus = Literal["ok", "degraded", "unavailable"]


class ComponentHealth(BaseModel):
    name: str
    status: ComponentStatus
    detail: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    app_name: str
    version: str
    components: list[ComponentHealth]
