"""Database models and engine configuration."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy models."""


engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
