"""Database models and engine configuration."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy models."""


def _init_engine():
    db_url = settings.database_url
    if db_url.startswith("sqlite"):
        return create_engine(db_url, connect_args={"check_same_thread": False}, future=True)
    try:
        eng = create_engine(db_url, pool_pre_ping=True, future=True)
        with eng.connect():
            pass
        return eng
    except Exception:
        if settings.app_env == "development":
            sqlite_eng = create_engine(
                "sqlite:///./cip_dev.db",
                connect_args={"check_same_thread": False},
                future=True,
            )
            return sqlite_eng
        raise


engine = _init_engine()
