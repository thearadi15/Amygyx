"""Finding model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.incident_finding import IncidentFinding
    from app.db.models.tenant import Tenant


class Finding(Base):
    """A single detection result tied to a tenant and evidence set."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id"),
        nullable=False,
        index=True,
    )
    source_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(30), nullable=False, default="low", index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    business_impact: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="moderate",
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open", index=True)
    rule_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    detector_version: Mapped[str | None] = mapped_column(String(60), nullable=True)
    evidence: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    tenant: Mapped[Tenant] = relationship(back_populates="findings")
    incident_links: Mapped[list[IncidentFinding]] = relationship(back_populates="finding")
