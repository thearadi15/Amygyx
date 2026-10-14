"""Tenant-scoped finding endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import require_role
from app.db.models import AuditEvent, Finding, User
from app.db.session import get_db
from app.schemas.finding import FindingCreate, FindingRead, FindingStatus, Severity

router = APIRouter(prefix="/findings", tags=["findings"])
DbSession = Annotated[Session, Depends(get_db)]
TenantMember = Annotated[User, Depends(require_role("admin", "analyst"))]


@router.post("", response_model=FindingRead, status_code=status.HTTP_201_CREATED)
def create_finding(payload: FindingCreate, db: DbSession, member: TenantMember) -> Finding:
    """Record a finding for the authenticated user's tenant."""

    now = datetime.now(UTC)
    finding = Finding(
        id=str(uuid.uuid4()),
        tenant_id=member.tenant_id,
        source_type=payload.source_type,
        source_id=payload.source_id,
        title=payload.title,
        summary=payload.summary,
        severity=payload.severity,
        confidence=payload.confidence,
        business_impact=payload.business_impact,
        status="open",
        rule_id=payload.rule_id,
        detector_version=payload.detector_version,
        evidence=payload.evidence,
        created_at=now,
        updated_at=now,
    )
    db.add(finding)
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
    db.commit()
    db.refresh(finding)
    return finding


@router.get("", response_model=list[FindingRead])
def list_findings(
    db: DbSession,
    member: TenantMember,
    severity: Severity | None = None,
    finding_status: Annotated[FindingStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Finding]:
    """List findings for the authenticated user's tenant only."""

    statement = select(Finding).where(Finding.tenant_id == member.tenant_id)
    if severity is not None:
        statement = statement.where(Finding.severity == severity)
    if finding_status is not None:
        statement = statement.where(Finding.status == finding_status)

    statement = (
        statement.order_by(Finding.created_at.desc(), Finding.id.asc()).offset(offset).limit(limit)
    )
    return list(db.scalars(statement).all())


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: str, db: DbSession, member: TenantMember) -> Finding:
    """Read a finding only when it belongs to the authenticated tenant."""

    finding = db.scalar(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.tenant_id == member.tenant_id,
        )
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return finding
