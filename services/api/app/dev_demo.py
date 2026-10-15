"""Explicit local-only account bootstrap for synthetic workflow demonstrations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import create_access_token
from app.config import get_settings
from app.db.base import Base, engine
from app.db.models import Tenant, User
from app.db.session import SessionLocal

DEMO_TENANT_ID = "00000000-0000-4000-8000-000000000001"
DEMO_USER_ID = "00000000-0000-4000-8000-000000000002"
DEMO_TENANT_SLUG = "local-synthetic-demo"
DEMO_EMAIL = "analyst@synthetic.example.test"
ADMIN_USER_ID = "00000000-0000-4000-8000-000000000003"
ADMIN_EMAIL = "admin@amygyx.io"


def ensure_demo_member(db: Session) -> User:
    """Create the documented synthetic tenant/member if absent; never modify existing data."""

    tenant = db.scalar(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))
    if tenant is None:
        tenant_id_collision = db.get(Tenant, DEMO_TENANT_ID)
        if tenant_id_collision is not None:
            raise RuntimeError("The local demo tenant ID is already assigned to another tenant.")
        tenant = Tenant(
            id=DEMO_TENANT_ID,
            name="Local Synthetic Demo",
            slug=DEMO_TENANT_SLUG,
        )
        db.add(tenant)
        db.flush()
    elif tenant.id != DEMO_TENANT_ID:
        raise RuntimeError("The local demo tenant slug is already assigned to another tenant.")

    member = db.scalar(select(User).where(User.id == DEMO_USER_ID))
    if member is None:
        email_collision = db.scalar(select(User).where(User.email == DEMO_EMAIL))
        if email_collision is not None:
            raise RuntimeError("The local demo email is already assigned to another user.")
        member = User(
            id=DEMO_USER_ID,
            tenant_id=DEMO_TENANT_ID,
            email=DEMO_EMAIL,
            full_name="Synthetic Demo Analyst",
            role="analyst",
        )
        db.add(member)
        db.flush()
    elif member.tenant_id != DEMO_TENANT_ID or member.role != "analyst":
        raise RuntimeError("The local demo user exists with an unexpected tenant or role.")

    return member


def ensure_admin_member(db: Session) -> User:
    """Ensure an administrator member exists in the local development tenant."""

    ensure_demo_member(db)
    admin = db.scalar(select(User).where(User.id == ADMIN_USER_ID))
    if admin is None:
        admin = User(
            id=ADMIN_USER_ID,
            tenant_id=DEMO_TENANT_ID,
            email=ADMIN_EMAIL,
            full_name="Platform Admin",
            role="admin",
        )
        db.add(admin)
        db.flush()
    return admin


def main() -> None:
    """Seed the local synthetic identity and print short-lived development tokens."""

    settings = get_settings()
    if settings.app_env != "development":
        raise SystemExit("Refusing local demo setup: APP_ENV must be development.")

    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        analyst = ensure_demo_member(db)
        admin = ensure_admin_member(db)
        db.commit()

        analyst_token = create_access_token(
            subject=analyst.id,
            tenant_id=analyst.tenant_id,
            email=analyst.email,
            role=analyst.role,
        )
        admin_token = create_access_token(
            subject=admin.id,
            tenant_id=admin.tenant_id,
            email=admin.email,
            role=admin.role,
        )

    print("=== AMYGYX LOCAL DEVELOPMENT API TOKENS ===")
    print(f"Tenant: {DEMO_TENANT_SLUG} ({DEMO_TENANT_ID})")
    print(f"Token TTL: {settings.auth_token_ttl_minutes} minutes\n")
    print("--- ADMIN TOKEN (role: admin, email: admin@amygyx.io) ---")
    print(admin_token)
    print("\n--- ANALYST TOKEN (role: analyst, email: analyst@synthetic.example.test) ---")
    print(analyst_token)


if __name__ == "__main__":
    main()
