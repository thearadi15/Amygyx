"""Create findings, incidents, and incident-link tables.

Revision ID: 20261012_000002
Revises: 20261012_000001
Create Date: 2026-10-12 23:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20261012_000002"
down_revision = "20261012_000001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the incident workflow tables."""

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("source_type", sa.String(length=100), nullable=False),
        sa.Column("source_id", sa.String(length=255), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=30), nullable=False, server_default="low"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="open"),
        sa.Column("rule_id", sa.String(length=120), nullable=True),
        sa.Column("detector_version", sa.String(length=60), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_findings_tenant_id"),
    )
    op.create_index(op.f("ix_findings_tenant_id"), "findings", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_findings_source_type"), "findings", ["source_type"], unique=False)
    op.create_index(op.f("ix_findings_source_id"), "findings", ["source_id"], unique=False)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)
    op.create_index(op.f("ix_findings_rule_id"), "findings", ["rule_id"], unique=False)

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=30), nullable=False, server_default="low"),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="new"),
        sa.Column("owner_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_incidents_tenant_id"),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], name="fk_incidents_owner_id"),
    )
    op.create_index(op.f("ix_incidents_tenant_id"), "incidents", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_incidents_severity"), "incidents", ["severity"], unique=False)
    op.create_index(op.f("ix_incidents_status"), "incidents", ["status"], unique=False)
    op.create_index(op.f("ix_incidents_owner_id"), "incidents", ["owner_id"], unique=False)

    op.create_table(
        "incident_findings",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name="fk_incident_findings_incident_id",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_incident_findings_finding_id",
        ),
    )
    op.create_index(
        op.f("ix_incident_findings_incident_id"),
        "incident_findings",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_findings_finding_id"),
        "incident_findings",
        ["finding_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop findings, incidents, and link tables."""

    op.drop_index(op.f("ix_incident_findings_finding_id"), table_name="incident_findings")
    op.drop_index(op.f("ix_incident_findings_incident_id"), table_name="incident_findings")
    op.drop_table("incident_findings")
    op.drop_index(op.f("ix_incidents_owner_id"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_status"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_severity"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_tenant_id"), table_name="incidents")
    op.drop_table("incidents")
    op.drop_index(op.f("ix_findings_rule_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_status"), table_name="findings")
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index(op.f("ix_findings_source_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_source_type"), table_name="findings")
    op.drop_index(op.f("ix_findings_tenant_id"), table_name="findings")
    op.drop_table("findings")
