"""Request and response contracts for incident workflows."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.finding import Severity

IncidentStatus = Literal["new", "investigating", "contained", "resolved", "closed"]


class IncidentCreate(BaseModel):
    """Input contract for creating an incident and optionally linking findings."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(min_length=1, max_length=255)
    summary: str | None = Field(default=None, max_length=10_000)
    severity: Severity = "low"
    finding_ids: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("finding_ids")
    @classmethod
    def require_unique_finding_ids(cls, finding_ids: list[str]) -> list[str]:
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding_ids must not contain duplicates.")
        return finding_ids


class IncidentStatusUpdate(BaseModel):
    """Input contract for requesting a controlled incident status transition."""

    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus


class IncidentFindingCreate(BaseModel):
    """Input contract for linking an existing finding to an incident."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=36)


class IncidentRead(BaseModel):
    """Public incident representation."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    summary: str | None
    severity: Severity
    status: IncidentStatus
    owner_id: str | None
    finding_ids: list[str]
    created_at: datetime
    updated_at: datetime
