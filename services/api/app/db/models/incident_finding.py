"""Incident-to-finding association model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.finding import Finding
    from app.db.models.incident import Incident


class IncidentFinding(Base):
    """Associates a finding with an incident and records the tie-time."""

    __tablename__ = "incident_findings"
    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "finding_id",
            name="uq_incident_findings_incident_finding",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    incident: Mapped[Incident] = relationship(back_populates="finding_links")
    finding: Mapped[Finding] = relationship(back_populates="incident_links")
