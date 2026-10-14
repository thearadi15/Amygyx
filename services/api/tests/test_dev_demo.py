"""Tests for the explicitly local synthetic demo bootstrap."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.auth import create_access_token, decode_access_token
from app.config import get_settings
from app.db.base import Base
from app.db.models import Tenant, User
from app.dev_demo import (
    DEMO_TENANT_ID,
    DEMO_TENANT_SLUG,
    DEMO_USER_ID,
    ensure_demo_member,
    main,
)


def test_demo_bootstrap_is_repeatable_and_does_not_escalate_role() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        first = ensure_demo_member(db)
        db.commit()
        second = ensure_demo_member(db)
        db.commit()

        assert first.id == second.id == DEMO_USER_ID
        assert first.tenant_id == second.tenant_id == DEMO_TENANT_ID
        assert second.role == "analyst"
        token = decode_access_token(
            create_access_token(
                subject=second.id,
                tenant_id=second.tenant_id,
                email=second.email,
                role=second.role,
            )
        )
        assert token["sub"] == DEMO_USER_ID
        assert token["tenant_id"] == DEMO_TENANT_ID
        assert token["role"] == "analyst"
        assert len(db.query(Tenant).filter_by(slug=DEMO_TENANT_SLUG).all()) == 1
        assert len(db.query(User).filter_by(id=DEMO_USER_ID).all()) == 1

    engine.dispose()


def test_demo_bootstrap_refuses_existing_user_with_different_role() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        ensure_demo_member(db)
        db.commit()
        member = db.get(User, DEMO_USER_ID)
        assert member is not None
        member.role = "admin"
        db.commit()

        with pytest.raises(RuntimeError, match="unexpected tenant or role"):
            ensure_demo_member(db)

    engine.dispose()


def test_demo_cli_refuses_non_development_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "app_env", "production")

    with pytest.raises(SystemExit, match="APP_ENV must be development"):
        main()
