"""Incident model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.incident_finding import IncidentFinding
    from app.db.models.tenant import Tenant
    from app.db.models.user import User


class Incident(Base):
    """A case that groups related findings and analyst investigation activity."""

    __tablename__ = "incidents"

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
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(30), nullable=False, default="low", index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="new", index=True)
    owner_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    tenant: Mapped[Tenant] = relationship(back_populates="incidents")
    owner: Mapped[User | None] = relationship(back_populates="owned_incidents")
    finding_links: Mapped[list[IncidentFinding]] = relationship(back_populates="incident")

    @property
    def finding_ids(self) -> list[str]:
        """Return the linked finding identifiers for API serialization."""

        return sorted(link.finding_id for link in self.finding_links)
