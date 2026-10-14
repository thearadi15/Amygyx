"""Versioned request and response contracts for findings."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]
BusinessImpact = Literal["low", "moderate", "high", "critical"]
FindingStatus = Literal["open", "investigating", "resolved", "false_positive"]


class FindingCreate(BaseModel):
    """Input contract for recording an explainable detection finding."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_type: str = Field(min_length=1, max_length=100)
    source_id: str | None = Field(default=None, max_length=255)
    title: str = Field(min_length=1, max_length=255)
    summary: str | None = Field(default=None, max_length=10_000)
    severity: Severity = "low"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    business_impact: BusinessImpact = "moderate"
    rule_id: str | None = Field(default=None, max_length=120)
    detector_version: str | None = Field(default=None, max_length=60)
    evidence: dict[str, Any] | None = None


class FindingRead(BaseModel):
    """Public finding representation."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    source_type: str
    source_id: str | None
    title: str
    summary: str | None
    severity: Severity
    confidence: float
    business_impact: BusinessImpact
    status: FindingStatus
    rule_id: str | None
    detector_version: str | None
    evidence: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime
