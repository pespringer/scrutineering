"""Database connection management — sync and async engines, session, init."""

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import Session, sessionmaker

from src.db.models import Base
from src.db.config import get_async_database_url, get_database_url
from src.db.pool_config import load_pool_config

DATABASE_URL = get_database_url("DATABASE_URL")

# Async variant for FastAPI
ASYNC_DATABASE_URL = get_async_database_url(DATABASE_URL)

# -- Sync engine (Celery workers) ------------------------------------------- #

engine_options = {"pool_pre_ping": True, "pool_recycle": 3600}
if not DATABASE_URL.startswith("sqlite"):
    engine_options.update(load_pool_config())

engine = create_engine(DATABASE_URL, **engine_options)


if not DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlalchemy_defaults(dbapi_connection, connection_record):
        """Tune connection-level settings on every PostgreSQL connection."""
        cursor = dbapi_connection.cursor()
        cursor.execute("SET timezone = 'UTC'")
        cursor.execute("SET work_mem = '16MB'")
        cursor.execute("SET statement_timeout = '300000'")
        cursor.close()

# -- Async engine (FastAPI) ------------------------------------------------ #

async_engine_options = {"pool_pre_ping": True, "pool_recycle": 3600, "echo": False}
if not ASYNC_DATABASE_URL.startswith("sqlite"):
    async_engine_options.update(load_pool_config())

async_engine = create_async_engine(ASYNC_DATABASE_URL, **async_engine_options)

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
