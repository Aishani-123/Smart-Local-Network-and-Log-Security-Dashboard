"""
db – Database package for Smart Local Network & Log Security Dashboard.

This package provides the SQLAlchemy declarative base and connection
utilities.  Importing this package does **not** establish a database
connection; connections are created lazily on first use.
"""

from db.base import Base
from db.connection import get_engine, get_session, get_session_factory

__all__ = ["Base", "get_engine", "get_session", "get_session_factory"]
