"""Shared response schema for local capability analysis profiles."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class CapabilityIndicatorRead(BaseModel):
    """An explainable module signal linked to the shared finding workflow."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    description: str
    severity: Literal["informational", "low", "medium", "high"]
    evidence: dict[str, str | int | float | bool]
    finding_id: str


class CapabilityAnalysisRead(BaseModel):
    """Shared result envelope for local-only capability analyzers."""

    model_config = ConfigDict(extra="forbid")

    capability_id: str
    result: Literal["no_indicators", "review_required"]
    ruleset_version: str
    records_processed: int
    summary: dict[str, str | int | float | bool]
    indicators: list[CapabilityIndicatorRead]
