"""Database connection management — sync and async engines, session, init."""

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import Session, sessionmaker

from src.db.models import Base

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://sentinel:sentinel@localhost:5432/sentinel"
)

# Async variant for FastAPI
ASYNC_DATABASE_URL = os.environ.get(
    "ASYNC_DATABASE_URL",
    DATABASE_URL.replace("postgresql+psycopg2://", "postgresql+asyncpg://")
              .replace("postgresql://", "postgresql+asyncpg://")
)

# -- Sync engine (Celery workers) ------------------------------------------- #

engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
)


@event.listens_for(engine, "connect")
def _set_sqlalchemy_defaults(dbapi_connection, connection_record):
    """Tune connection-level settings on every new connection."""
    cursor = dbapi_connection.cursor()
    # Timezone-aware timestamps
    cursor.execute("SET timezone = 'UTC'")
    # Slightly larger work_mem for analytical queries
    cursor.execute("SET work_mem = '16MB'")
    # Statement timeout as safety net (5 minutes)
    cursor.execute("SET statement_timeout = '300000'")
    cursor.close()

# -- Async engine (FastAPI) ------------------------------------------------ #

async_engine = create_async_engine(
    ASYNC_DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
    echo=False,
)

async_session_factory = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# -- Sync session factory --------------------------------------------------- #

session_factory = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    """Create all tables — mainly for testing / quick start."""
    Base.metadata.create_all(engine)


# -- Session helpers -------------------------------------------------------- #

@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Provide a transactional session that commits on success."""
    session: Session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


async def get_async_session() -> Generator[AsyncSession, None, None]:
    """Async session dependency for FastAPI endpoints."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
