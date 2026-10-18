"""
db.base – SQLAlchemy 2.x declarative base.

All ORM models should inherit from :class:`Base` defined here.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all database models."""

    pass
