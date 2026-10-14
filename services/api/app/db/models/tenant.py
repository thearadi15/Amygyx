"""Tenant model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.audit_event import AuditEvent
    from app.db.models.finding import Finding
    from app.db.models.incident import Incident
    from app.db.models.user import User


class Tenant(Base):
    """An isolated customer or business environment."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    users: Mapped[list[User]] = relationship(back_populates="tenant")
    audit_events: Mapped[list[AuditEvent]] = relationship(back_populates="tenant")
    findings: Mapped[list[Finding]] = relationship(back_populates="tenant")
    incidents: Mapped[list[Incident]] = relationship(back_populates="tenant")
