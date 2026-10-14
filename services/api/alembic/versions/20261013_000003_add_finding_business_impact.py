"""Add the independent business impact finding dimension.

Revision ID: 20261013_000003
Revises: 20261012_000002
Create Date: 2026-10-13 21:15:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
# revision identifiers, used by Alembic.
revision = "20261013_000003"
down_revision = "20261012_000002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add business impact without conflating it with severity or confidence."""

    op.add_column(
        "findings",
        sa.Column(
            "business_impact",
            sa.String(length=30),
            nullable=False,
            server_default="moderate",
        ),
    )
    op.alter_column("findings", "business_impact", server_default=None)


def downgrade() -> None:
    """Remove the business impact dimension."""

    op.drop_column("findings", "business_impact")
