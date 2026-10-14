"""Contracts for manual email analysis."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.schemas.finding import Severity


class EmailIndicatorRead(BaseModel):
    """A single explainable rule signal."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    description: str
    evidence: dict[str, str]
    severity: Severity


class EmailAnalysisRead(BaseModel):
    """Sanitized analysis response; it excludes body text and full URLs."""

    model_config = ConfigDict(extra="forbid")

    result: Literal["no_indicators", "suspicious_indicators"]
    ruleset_version: str
    sender_domain: str | None
    return_path_domain: str | None
    reply_to_domain: str | None
    urls: list[dict[str, str | bool]]
    urls_truncated: bool
    authentication_results: list[dict[str, str]]
    authentication_results_source: Literal["unverified_message_header"]
    indicators: list[EmailIndicatorRead]
    finding_id: str | None
