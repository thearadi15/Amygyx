"""User model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.audit_event import AuditEvent
    from app.db.models.incident import Incident
    from app.db.models.tenant import Tenant


class User(Base):
    """A user belonging to a tenant and assigned a role."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint(
            "identity_issuer",
            "identity_subject",
            name="uq_users_identity_issuer_subject",
        ),
    )

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
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="analyst")
    identity_issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    identity_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    tenant: Mapped[Tenant] = relationship(back_populates="users")
    audit_events: Mapped[list[AuditEvent]] = relationship(back_populates="actor")
    owned_incidents: Mapped[list[Incident]] = relationship(back_populates="owner")
