"""Database connection manager for Project Vero.
Connects to Cloud PostgreSQL (Neon, Supabase, AWS RDS, GCP Cloud SQL) using asyncpg/psycopg,
with an automatic local fallback for testing and development environments.
"""

import os
import re
import ssl
from typing import AsyncGenerator, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text

from api_agents.db.models import Base

_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None


def normalize_database_url(raw_url: str) -> tuple[str, dict]:
    """Normalize raw PostgreSQL URLs (e.g. from Neon, Supabase, Render, Heroku)

    to an SQLAlchemy asyncpg or psycopg compatible URL and connect_args.
    """
    connect_args: dict = {}
    url = raw_url.strip()

    # Convert generic postgres:// or postgresql:// to postgresql+asyncpg://
    if url.startswith("postgres://"):
        url = "postgresql+asyncpg://" + url[len("postgres://"):]
    elif url.startswith("postgresql://") and not url.startswith("postgresql+"):
        url = "postgresql+asyncpg://" + url[len("postgresql://"):]

    # Handle SSL for Cloud PostgreSQL providers
    if "asyncpg" in url:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # asyncpg prefers ssl parameter as boolean or SSLContext
        sslmode = query_params.pop("sslmode", [None])[0]
        if sslmode in ("require", "verify-ca", "verify-full") or "ssl" in query_params:
            query_params.pop("ssl", None)
            ctx = ssl.create_default_context()
            if sslmode == "require":
                # For cloud pools that use self-signed certificates or proxy endpoints
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            connect_args["ssl"] = ctx

        new_query = urlencode(query_params, doseq=True)
        url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

    return url, connect_args


def get_database_url() -> tuple[str, str, dict]:
    """Retrieve database URL from environment variables or use fallback.

    Returns: (url, db_type, connect_args)
    """
    env_keys = ["DATABASE_URL", "VERO_DATABASE_URL", "POSTGRES_URL", "PG_URL"]
    for key in env_keys:
        val = os.getenv(key)
        if val and val.strip():
            norm_url, connect_args = normalize_database_url(val)
            return norm_url, "cloud_postgresql", connect_args

    # Fallback to local SQLite for development and offline testing
    fallback_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "vero_snapshots.db")
    )
    fallback_url = f"sqlite+aiosqlite:///{fallback_path}"
    return fallback_url, "sqlite_fallback", {}


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        url, db_type, connect_args = get_database_url()
        if db_type == "cloud_postgresql":
            _engine = create_async_engine(
                url,
                connect_args=connect_args,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                echo=False,
            )
        else:
            _engine = create_async_engine(
                url,
                connect_args=connect_args,
                echo=False,
            )
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        engine = get_engine()
        _sessionmaker = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _sessionmaker


async def init_db() -> None:
    """Initialize database tables."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close active database engine pool."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _sessionmaker = None


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for yielding database sessions."""
    sm = get_sessionmaker()
    async with sm() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_db_status() -> dict:
    """Health check for database connectivity."""
    url, db_type, _ = get_database_url()
    engine = get_engine()

    # Redact credentials for safe public display
    redacted_url = re.sub(r"://([^:@]+):([^@]+)@", r"://\1:***@", url)

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        connected = True
        error = None
    except Exception as e:
        connected = False
        error = str(e)

    return {
        "connected": connected,
        "database_type": db_type,
        "is_cloud_postgres": db_type == "cloud_postgresql",
        "redacted_target": redacted_url,
        "error": error,
    }
