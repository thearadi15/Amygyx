"""Shared API test fixtures."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import Tenant, User
from app.db.session import get_db
from app.main import app


@pytest.fixture
def api_client() -> Generator[TestClient, None, None]:
    """Create an isolated database and tenant fixtures per API test."""

    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(test_engine)
    test_session = sessionmaker(
        bind=test_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    def override_get_db() -> Generator[Session, None, None]:
        db = test_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.test_session = test_session
    with test_session() as db:
        db.add_all(
            [
                Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"),
                Tenant(id="tenant-b", name="Tenant B", slug="tenant-b"),
            ]
        )
        db.flush()
        db.add_all(
            [
                User(
                    id="user-a",
                    tenant_id="tenant-a",
                    email="analyst-a@example.test",
                    full_name="Analyst A",
                    role="analyst",
                ),
                User(
                    id="user-b",
                    tenant_id="tenant-b",
                    email="analyst-b@example.test",
                    full_name="Analyst B",
                    role="analyst",
                ),
            ]
        )
        db.commit()

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.pop(get_db, None)
    del app.state.test_session
    test_engine.dispose()
