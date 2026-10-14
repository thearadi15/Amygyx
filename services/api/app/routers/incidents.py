"""Tenant-scoped incident workflow endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.auth import require_role
from app.db.models import AuditEvent, Finding, Incident, IncidentFinding, User
from app.db.session import get_db
from app.schemas.finding import Severity
from app.schemas.incident import (
    IncidentCreate,
    IncidentFindingCreate,
    IncidentRead,
    IncidentStatus,
    IncidentStatusUpdate,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])
DbSession = Annotated[Session, Depends(get_db)]
TenantMember = Annotated[User, Depends(require_role("admin", "analyst"))]

STATUS_TRANSITIONS: dict[str, frozenset[IncidentStatus]] = {
    "new": frozenset({"investigating"}),
    "investigating": frozenset({"contained", "resolved"}),
    "contained": frozenset({"investigating", "resolved"}),
    "resolved": frozenset({"investigating", "closed"}),
    "closed": frozenset(),
}


def _get_incident(db: Session, incident_id: str, tenant_id: str) -> Incident:
    incident = db.scalar(
        select(Incident)
        .options(selectinload(Incident.finding_links))
        .where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
        .execution_options(populate_existing=True)
    )
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return incident


def _validate_tenant_findings(
    db: Session,
    finding_ids: list[str],
    tenant_id: str,
) -> list[Finding]:
    if not finding_ids:
        return []

    findings = list(
        db.scalars(
            select(Finding).where(
                Finding.tenant_id == tenant_id,
                Finding.id.in_(finding_ids),
            )
        ).all()
    )
    if len(findings) != len(finding_ids):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return findings


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident(payload: IncidentCreate, db: DbSession, member: TenantMember) -> Incident:
    """Create an incident for the caller's tenant and link only that tenant's findings."""

    linked_findings = _validate_tenant_findings(db, payload.finding_ids, member.tenant_id)
    now = datetime.now(UTC)
    incident = Incident(
        id=str(uuid.uuid4()),
        tenant_id=member.tenant_id,
        title=payload.title,
        summary=payload.summary,
        severity=payload.severity,
        status="new",
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()

    for finding in linked_findings:
        db.add(
            IncidentFinding(
                id=str(uuid.uuid4()),
                incident_id=incident.id,
                finding_id=finding.id,
                created_at=now,
            )
        )
        db.add(
            AuditEvent(
                tenant_id=member.tenant_id,
                actor_id=member.id,
                event_type="incident.finding_linked",
                resource_type="incident",
                resource_id=incident.id,
                event_data={"finding_id": finding.id},
                created_at=now,
            )
        )

    db.add(
        AuditEvent(
            tenant_id=member.tenant_id,
            actor_id=member.id,
            event_type="incident.created",
            resource_type="incident",
            resource_id=incident.id,
            event_data={"severity": incident.severity, "finding_count": len(linked_findings)},
            created_at=now,
        )
    )
    db.commit()
    return _get_incident(db, incident.id, member.tenant_id)


@router.get("", response_model=list[IncidentRead])
def list_incidents(
    db: DbSession,
    member: TenantMember,
    severity: Severity | None = None,
    incident_status: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Incident]:
    """List incidents for the authenticated tenant with bounded pagination."""

    statement = (
        select(Incident)
        .options(selectinload(Incident.finding_links))
        .where(Incident.tenant_id == member.tenant_id)
    )
    if severity is not None:
        statement = statement.where(Incident.severity == severity)
    if incident_status is not None:
        statement = statement.where(Incident.status == incident_status)

    statement = (
        statement.order_by(Incident.created_at.desc(), Incident.id.asc())
        .offset(offset)
        .limit(limit)
    )
    return list(db.scalars(statement).all())


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(incident_id: str, db: DbSession, member: TenantMember) -> Incident:
    """Read an incident only when it belongs to the authenticated tenant."""

    return _get_incident(db, incident_id, member.tenant_id)


@router.patch("/{incident_id}/status", response_model=IncidentRead)
def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: DbSession,
    member: TenantMember,
) -> Incident:
    """Apply an allowed incident state transition and record it in the audit log."""

    incident = _get_incident(db, incident_id, member.tenant_id)
    allowed_transitions = STATUS_TRANSITIONS.get(incident.status)
    if allowed_transitions is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident has an unsupported current status.",
        )
    current_status = incident.status
    if payload.status not in allowed_transitions:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot transition incident from '{current_status}' to '{payload.status}'.",
        )

    now = datetime.now(UTC)
    incident.status = payload.status
    incident.updated_at = now
    db.add(
        AuditEvent(
            tenant_id=member.tenant_id,
            actor_id=member.id,
            event_type="incident.status_changed",
            resource_type="incident",
            resource_id=incident.id,
            event_data={"from_status": current_status, "to_status": payload.status},
            created_at=now,
        )
    )
    db.commit()
    return _get_incident(db, incident.id, member.tenant_id)


@router.post(
    "/{incident_id}/findings",
    response_model=IncidentRead,
    status_code=status.HTTP_200_OK,
)
def link_finding_to_incident(
    incident_id: str,
    payload: IncidentFindingCreate,
    db: DbSession,
    member: TenantMember,
) -> Incident:
    """Link an existing finding after validating that it shares the incident's tenant."""

    incident = _get_incident(db, incident_id, member.tenant_id)
    finding = db.scalar(
        select(Finding).where(
            Finding.id == payload.finding_id,
            Finding.tenant_id == member.tenant_id,
        )
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    existing_link = db.scalar(
        select(IncidentFinding).where(
            IncidentFinding.incident_id == incident.id,
            IncidentFinding.finding_id == finding.id,
        )
    )
    if existing_link is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Finding is already linked to this incident.",
        )

    now = datetime.now(UTC)
    db.add(
        IncidentFinding(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            finding_id=finding.id,
            created_at=now,
        )
    )
    incident.updated_at = now
    db.add(
        AuditEvent(
            tenant_id=member.tenant_id,
            actor_id=member.id,
            event_type="incident.finding_linked",
            resource_type="incident",
            resource_id=incident.id,
            event_data={"finding_id": finding.id},
            created_at=now,
        )
    )
    db.commit()
    return _get_incident(db, incident.id, member.tenant_id)
