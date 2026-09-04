from pydantic import BaseModel, Field

from app.attribution.ioc import Ioc


class IocListResponse(BaseModel):
    case_id: str
    iocs: list[Ioc]


class AnalystNotesUpdate(BaseModel):
    notes: str = Field(max_length=4096)
