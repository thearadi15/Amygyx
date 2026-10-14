"""Tests for the tenant-aware database model metadata."""

from app.db.base import Base
from app.db.models import AuditEvent, Tenant, User


def test_database_metadata_exposes_expected_tables() -> None:
    assert {"tenants", "users", "audit_events"}.issubset(set(Base.metadata.tables))


def test_database_models_are_registered() -> None:
    assert Tenant.__tablename__ == "tenants"
    assert User.__tablename__ == "users"
    assert AuditEvent.__tablename__ == "audit_events"
