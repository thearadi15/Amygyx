"""Add external OIDC identity mappings to tenant members.

Revision ID: 20261013_000005
Revises: 20261013_000004
Create Date: 2026-10-13 21:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20261013_000005"
down_revision = "20261013_000004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Store the OIDC issuer and subject linked to each authorized tenant member."""

    op.add_column("users", sa.Column("identity_issuer", sa.String(length=500), nullable=True))
    op.add_column("users", sa.Column("identity_subject", sa.String(length=255), nullable=True))
    op.create_unique_constraint(
        "uq_users_identity_issuer_subject",
        "users",
        ["identity_issuer", "identity_subject"],
    )


def downgrade() -> None:
    """Remove external identity mappings."""

    op.drop_constraint("uq_users_identity_issuer_subject", "users", type_="unique")
    op.drop_column("users", "identity_subject")
    op.drop_column("users", "identity_issuer")
