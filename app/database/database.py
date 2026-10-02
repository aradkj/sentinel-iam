from typing import Any

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from app.core.config import settings

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy 2.x ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def build_async_engine(database_url: str | None = None) -> AsyncEngine:
    """Create and configure a SQLAlchemy 2.x AsyncEngine."""
    url = database_url or settings.async_database_url
    engine_kwargs: dict[str, Any] = {
        "echo": settings.APP_DEBUG,
        "future": True,
    }
    if url.startswith("sqlite"):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    elif settings.APP_ENV == "test":
        engine_kwargs["poolclass"] = NullPool
    else:
        engine_kwargs["pool_pre_ping"] = True
        engine_kwargs["pool_size"] = 10
        engine_kwargs["max_overflow"] = 20

    return create_async_engine(url, **engine_kwargs)


engine: AsyncEngine = build_async_engine()
