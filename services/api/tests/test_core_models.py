"""Tests for the core security workflow models."""

from app.db.base import Base
from app.db.models import Finding, Incident, IncidentFinding, Tenant, User


def test_core_security_models_register_metadata() -> None:
    expected = {"tenants", "users", "audit_events", "findings", "incidents", "incident_findings"}
    assert expected.issubset(set(Base.metadata.tables))


def test_core_security_models_are_exposed() -> None:
    assert Finding.__tablename__ == "findings"
    assert Incident.__tablename__ == "incidents"
    assert IncidentFinding.__tablename__ == "incident_findings"
    assert Tenant.__tablename__ == "tenants"
    assert User.__tablename__ == "users"
