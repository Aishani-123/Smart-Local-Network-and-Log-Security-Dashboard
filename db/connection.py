"""
db.connection – Lazy database connection utilities.

All connection objects are created on first call and cached for the
lifetime of the process.  Importing this module does **not** open a
connection to PostgreSQL.
"""

from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

# Load .env once at import time (no-op if the file does not exist).
load_dotenv()


def get_database_url() -> str:
    """Return the ``DATABASE_URL`` environment variable.

    Raises
    ------
    RuntimeError
        If ``DATABASE_URL`` is not set or is empty.
    """
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set.  "
            "Create a .env file (see .env.example) or export the variable "
            "before starting the application."
        )
    return url


# ---------------------------------------------------------------------------
# Engine & session factory (cached / lazy)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_engine():
    """Create and return a cached :class:`~sqlalchemy.engine.Engine`.

    The engine uses ``pool_pre_ping=True`` so that stale connections are
    recycled transparently.
    """
    return create_engine(
        get_database_url(),
        pool_pre_ping=True,
    )


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    """Return a cached :class:`~sqlalchemy.orm.sessionmaker` bound to the
    default engine.

    Sessions produced by this factory have ``autoflush=False`` and
    ``expire_on_commit=False`` for explicit, predictable behaviour.
    """
    return sessionmaker(
        bind=get_engine(),
        autoflush=False,
        expire_on_commit=False,
    )


def get_session() -> Session:
    """Create and return a new :class:`~sqlalchemy.orm.Session`."""
    return get_session_factory()()
