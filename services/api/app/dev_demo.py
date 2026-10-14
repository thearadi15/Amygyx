"""Explicit local-only account bootstrap for synthetic workflow demonstrations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import create_access_token
from app.config import get_settings
from app.db.models import Tenant, User
from app.db.session import SessionLocal

DEMO_TENANT_ID = "00000000-0000-4000-8000-000000000001"
DEMO_USER_ID = "00000000-0000-4000-8000-000000000002"
DEMO_TENANT_SLUG = "local-synthetic-demo"
DEMO_EMAIL = "analyst@synthetic.example.test"


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


def main() -> None:
    """Seed the local synthetic identity and print a short-lived development token."""

    settings = get_settings()
    if settings.app_env != "development":
        raise SystemExit("Refusing local demo setup: APP_ENV must be development.")

    with SessionLocal() as db:
        member = ensure_demo_member(db)
        db.commit()
        token = create_access_token(
            subject=member.id,
            tenant_id=member.tenant_id,
            email=member.email,
            role=member.role,
        )

    print("LOCAL DEVELOPMENT DEMO ONLY — not real authentication.")
    print(f"Tenant: {DEMO_TENANT_SLUG} ({DEMO_TENANT_ID})")
    print(f"User: {DEMO_EMAIL} (analyst)")
    print(f"Token expires in {settings.auth_token_ttl_minutes} minutes:")
    print(token)


if __name__ == "__main__":
    main()
