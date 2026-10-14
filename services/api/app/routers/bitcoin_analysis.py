"""Authenticated endpoint for offline Bitcoin transfer CSV analysis."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth import require_role
from app.bitcoin_analysis import (
    BITCOIN_RULESET_VERSION,
    InvalidBitcoinData,
    analyze_bitcoin_transfers,
)
from app.db.models import AuditEvent, Finding, User
from app.db.session import get_db
from app.schemas.bitcoin_analysis import BitcoinAnalysisRead, BitcoinIndicatorRead

MAX_BITCOIN_BYTES = 1_048_576

router = APIRouter(prefix="/bitcoin", tags=["Bitcoin transaction analysis"])
DbSession = Annotated[Session, Depends(get_db)]
TenantMember = Annotated[User, Depends(require_role("admin", "analyst"))]


async def _read_bounded_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BITCOIN_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="Transaction CSV exceeds the 1 MiB upload limit.",
            )
        body.extend(chunk)
    return bytes(body)


@router.post("/analyze", response_model=BitcoinAnalysisRead)
async def analyze_uploaded_transfers(
    request: Request,
    db: DbSession,
    member: TenantMember,
) -> BitcoinAnalysisRead:
    """Analyze uploaded transfer edges and persist only aggregate evidence and audit metadata."""

    raw_csv = await _read_bounded_body(request)
    try:
        analysis = analyze_bitcoin_transfers(raw_csv)
    except InvalidBitcoinData as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    now = datetime.now(UTC)
    response_indicators: list[BitcoinIndicatorRead] = []
    for indicator in analysis.indicators:
        finding = Finding(
            id=str(uuid.uuid4()),
            tenant_id=member.tenant_id,
            source_type="bitcoin_transaction",
            title=indicator.description.split(";")[0],
            summary=indicator.description,
            severity=indicator.severity,
            confidence=0.5,
            business_impact="moderate",
            status="open",
            rule_id=indicator.rule_id,
            detector_version=BITCOIN_RULESET_VERSION,
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
            BitcoinIndicatorRead(
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
            event_type="bitcoin.analyzed",
            resource_type=None,
            resource_id=None,
            event_data={
                "ruleset_version": BITCOIN_RULESET_VERSION,
                "indicator_count": len(analysis.indicators),
                "rows_processed": analysis.rows_processed,
                "upload_bytes": len(raw_csv),
            },
            created_at=now,
        )
    )
    db.commit()

    return BitcoinAnalysisRead(
        result="suspicious_indicators" if response_indicators else "no_indicators",
        ruleset_version=BITCOIN_RULESET_VERSION,
        rows_processed=analysis.rows_processed,
        indicators=response_indicators,
    )
