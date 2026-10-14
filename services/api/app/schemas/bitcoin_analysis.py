"""Response contracts for offline Bitcoin transfer analysis."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class BitcoinIndicatorRead(BaseModel):
    """An explainable ledger-pattern lead, not an identity or wrongdoing claim."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    description: str
    severity: Literal["low", "medium", "high"]
    evidence: dict[str, str | int]
    finding_id: str


class BitcoinAnalysisRead(BaseModel):
    """Aggregate result for a user-supplied Bitcoin transfer CSV."""

    model_config = ConfigDict(extra="forbid")

    result: Literal["no_indicators", "suspicious_indicators"]
    ruleset_version: str
    rows_processed: int
    indicators: list[BitcoinIndicatorRead]
