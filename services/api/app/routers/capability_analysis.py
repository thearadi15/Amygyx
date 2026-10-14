"""Authenticated, bounded endpoints for local-only capability analysis profiles."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.auth import require_role
from app.capability_analysis import (
    CapabilityAnalysis,
    CapabilityIndicator,
    InvalidCapabilityInput,
    dispatch_capability_analysis,
)
from app.db.models import AuditEvent, Finding, User
from app.db.session import get_db
from app.schemas.capability_analysis import CapabilityAnalysisRead, CapabilityIndicatorRead

MAX_CAPABILITY_BYTES = 1_048_576
CAPABILITY_VERSIONS = {
    "voice": "voice-signal-integrity-v1",
    "risk": "risk-investment-v1",
    "forecasting": "network-trend-v1",
    "compliance": "cisco-ios-baseline-v1",
    "identity": "document-structure-v1",
    "video": "cctv-event-metadata-v1",
    "ipsec": "strongswan-ipsec-baseline-v1",
}
CAPABILITY_SOURCE_TYPES = {
    "voice": "voice_audio_review",
    "risk": "cyber_risk_investment",
    "forecasting": "network_trend_analysis",
    "compliance": "network_security_compliance",
    "identity": "document_structure_review",
    "video": "cctv_event_metadata",
    "ipsec": "ipsec_configuration",
}

router = APIRouter(prefix="/capabilities", tags=["local capability analysis"])
DbSession = Annotated[Session, Depends(get_db)]
TenantMember = Annotated[User, Depends(require_role("admin", "analyst"))]


async def _read_bounded_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_CAPABILITY_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="Capability upload exceeds the 1 MiB upload limit.",
            )
        body.extend(chunk)
    return bytes(body)


def _finding_title(indicator: CapabilityIndicator) -> str:
    sentence = indicator.description.split(".", maxsplit=1)[0].strip()
    return sentence[:255] or indicator.rule_id


def _persist_analysis(
    db: Session,
    member: User,
    capability_id: str,
    analysis: CapabilityAnalysis,
    raw_size: int,
) -> list[CapabilityIndicatorRead]:
    now = datetime.now(UTC)
    response_indicators: list[CapabilityIndicatorRead] = []
    for indicator in analysis.indicators[:100]:
        finding = Finding(
            id=str(uuid.uuid4()),
            tenant_id=member.tenant_id,
            source_type=CAPABILITY_SOURCE_TYPES[capability_id],
            title=_finding_title(indicator),
            summary=indicator.description,
            severity=indicator.severity,
            confidence=0.5,
            business_impact="moderate",
            status="open",
            rule_id=indicator.rule_id,
            detector_version=CAPABILITY_VERSIONS[capability_id],
            evidence=indicator.evidence,
            created_at=now,
            updated_at=now,
        )
        db.add(finding)
        db.flush()
        db.add(
            AuditEvent(
                tenant_id=member.tenant_id,
                actor_id=member.id,
                event_type="finding.created",
                resource_type="finding",
                resource_id=finding.id,
                event_data={
                    "source_type": finding.source_type,
                    "severity": finding.severity,
                },
                created_at=now,
            )
        )
        response_indicators.append(
            CapabilityIndicatorRead(
                rule_id=indicator.rule_id,
                description=indicator.description,
                severity=indicator.severity,
                evidence=indicator.evidence,
                finding_id=finding.id,
            )
        )

    db.add(
        AuditEvent(
            tenant_id=member.tenant_id,
            actor_id=member.id,
            event_type=f"capability.{capability_id}.analyzed",
            resource_type=None,
            resource_id=None,
            event_data={
                "ruleset_version": CAPABILITY_VERSIONS[capability_id],
                "indicator_count": len(analysis.indicators),
                "records_processed": analysis.records_processed,
                "upload_bytes": raw_size,
            },
            created_at=now,
        )
    )
    db.commit()
    return response_indicators


@router.post("/{capability_id}/analyze", response_model=CapabilityAnalysisRead)
async def analyze_capability_upload(
    capability_id: str,
    request: Request,
    db: DbSession,
    member: TenantMember,
    filename: Annotated[str, Query(min_length=1, max_length=255)],
    budget_usd: Annotated[float | None, Query(ge=0, le=1_000_000)] = None,
) -> CapabilityAnalysisRead:
    """Analyze a supported local profile and save only findings and audit summaries."""

    if capability_id not in CAPABILITY_VERSIONS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Local analyzer profile not found.",
        )
    if budget_usd is not None and capability_id != "risk":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="budget_usd is supported only by the risk capability.",
        )
    raw_data = await _read_bounded_body(request)
    try:
        analysis = dispatch_capability_analysis(
            capability_id,
            raw_data,
            filename,
            budget_usd=budget_usd,
        )
    except InvalidCapabilityInput as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    response_indicators = _persist_analysis(
        db,
        member,
        capability_id,
        analysis,
        len(raw_data),
    )
    return CapabilityAnalysisRead(
        capability_id=capability_id,
        result="review_required" if response_indicators else "no_indicators",
        ruleset_version=CAPABILITY_VERSIONS[capability_id],
        records_processed=analysis.records_processed,
        summary=analysis.summary,
        indicators=response_indicators,
    )
