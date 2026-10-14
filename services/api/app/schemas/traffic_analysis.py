"""Request-independent response contracts for unidirectional traffic analysis."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class TrafficIndicatorRead(BaseModel):
    """An explainable, non-verdict traffic signal."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    description: str
    severity: Literal["low", "medium", "high"]
    evidence: dict[str, str | int]
    finding_id: str


class TrafficAnalysisRead(BaseModel):
    """Aggregate result for an uploaded one-way flow CSV."""

    model_config = ConfigDict(extra="forbid")

    result: Literal["no_indicators", "suspicious_indicators"]
    ruleset_version: str
    rows_processed: int
    indicators: list[TrafficIndicatorRead]
