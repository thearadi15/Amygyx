"""Prevent duplicate incident-to-finding links.

Revision ID: 20261013_000004
Revises: 20261013_000003
Create Date: 2026-10-13 21:13:00
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "20261013_000004"
down_revision = "20261013_000003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Enforce one link per incident and finding pair."""

    op.create_unique_constraint(
        "uq_incident_findings_incident_finding",
        "incident_findings",
        ["incident_id", "finding_id"],
    )


def downgrade() -> None:
    """Remove the incident-to-finding uniqueness constraint."""

    op.drop_constraint(
        "uq_incident_findings_incident_finding",
        "incident_findings",
        type_="unique",
    )
