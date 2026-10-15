"""
db.models – SQLAlchemy ORM models for hosts and system scan runs.

Defines the initial schema entities for tracking observed hosts and system-level
metrics snapshots over time.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base


class Host(Base):
    """Represents a monitored host machine."""

    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    operating_system: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    scan_runs: Mapped[List[ScanRun]] = relationship(
        "ScanRun",
        back_populates="host",
        passive_deletes="all",
    )

    def __repr__(self) -> str:
        return f"<Host(id={self.id}, hostname='{self.hostname}')>"


class ScanRun(Base):
    """Represents a discrete system-monitoring metrics snapshot for a host."""

    __tablename__ = "scan_runs"

    __table_args__ = (
        CheckConstraint(
            "cpu_usage_percent >= 0.0 AND cpu_usage_percent <= 100.0",
            name="ck_scan_runs_cpu_usage_percent_range",
        ),
        CheckConstraint(
            "memory_usage_percent >= 0.0 AND memory_usage_percent <= 100.0",
            name="ck_scan_runs_memory_usage_percent_range",
        ),
        CheckConstraint(
            "process_count >= 0",
            name="ck_scan_runs_process_count_non_negative",
        ),
        CheckConstraint(
            "connection_count >= 0",
            name="ck_scan_runs_connection_count_non_negative",
        ),
        Index("ix_scan_runs_host_id_captured_at", "host_id", "captured_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("hosts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    cpu_usage_percent: Mapped[float] = mapped_column(Float, nullable=False)
    memory_usage_percent: Mapped[float] = mapped_column(Float, nullable=False)
    process_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    connection_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    # Relationships
    host: Mapped[Host] = relationship(
        "Host",
        back_populates="scan_runs",
    )

    def __repr__(self) -> str:
        return (
            f"<ScanRun(id={self.id}, host_id={self.host_id}, "
            f"captured_at='{self.captured_at}', cpu={self.cpu_usage_percent}%, "
            f"memory={self.memory_usage_percent}%)>"
        )
