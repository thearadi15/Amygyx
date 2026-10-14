"""Database session helpers."""

from collections.abc import Generator

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import engine

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """Provide a SQLAlchemy session for request-scoped database access."""

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database_available() -> bool:
    """Return True when the configured PostgreSQL instance is reachable."""

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
