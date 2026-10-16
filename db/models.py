"""
db.models – SQLAlchemy ORM models for hosts, scan runs, process observations,
network connections, security events, and response actions.

Defines schema entities for tracking observed hosts, system-level metrics
snapshots, per-process telemetry/ML scores, active network connections,
security events, and response actions taken.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET
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
    security_events: Mapped[List[SecurityEvent]] = relationship(
        "SecurityEvent",
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
    process_observations: Mapped[List[ProcessObservation]] = relationship(
        "ProcessObservation",
        back_populates="scan_run",
        passive_deletes="all",
    )
    network_connections: Mapped[List[NetworkConnection]] = relationship(
        "NetworkConnection",
        back_populates="scan_run",
        passive_deletes="all",
    )
    security_events: Mapped[List[SecurityEvent]] = relationship(
        "SecurityEvent",
        back_populates="scan_run",
        passive_deletes="all",
    )

    def __repr__(self) -> str:
        return (
            f"<ScanRun(id={self.id}, host_id={self.host_id}, "
            f"captured_at='{self.captured_at}', cpu={self.cpu_usage_percent}%, "
            f"memory={self.memory_usage_percent}%)>"
        )


class ProcessObservation(Base):
    """Represents a process-level telemetry and anomaly detection snapshot within a scan."""

    __tablename__ = "process_observations"

    __table_args__ = (
        UniqueConstraint("scan_id", "pid", name="uq_process_observations_scan_id_pid"),
        CheckConstraint(
            "cpu_usage_percent IS NULL OR cpu_usage_percent >= 0.0",
            name="ck_process_observations_cpu_usage_percent_non_negative",
        ),
        CheckConstraint(
            "memory_usage_percent IS NULL OR (memory_usage_percent >= 0.0 AND memory_usage_percent <= 100.0)",
            name="ck_process_observations_memory_usage_percent_range",
        ),
        CheckConstraint(
            "process_size_mb IS NULL OR process_size_mb >= 0.0",
            name="ck_process_observations_process_size_mb_non_negative",
        ),
        CheckConstraint(
            "memory_usage_mb IS NULL OR memory_usage_mb >= 0.0",
            name="ck_process_observations_memory_usage_mb_non_negative",
        ),
        CheckConstraint(
            "execution_time_sec IS NULL OR execution_time_sec >= 0.0",
            name="ck_process_observations_execution_time_sec_non_negative",
        ),
        CheckConstraint(
            "thread_count IS NULL OR thread_count >= 0",
            name="ck_process_observations_thread_count_non_negative",
        ),
        CheckConstraint(
            "network_connections IS NULL OR network_connections >= 0",
            name="ck_process_observations_network_connections_non_negative",
        ),
        CheckConstraint(
            "bytes_sent_mb IS NULL OR bytes_sent_mb >= 0.0",
            name="ck_process_observations_bytes_sent_mb_non_negative",
        ),
        CheckConstraint(
            "failed_accesses IS NULL OR failed_accesses >= 0",
            name="ck_process_observations_failed_accesses_non_negative",
        ),
        CheckConstraint(
            "file_operations IS NULL OR file_operations >= 0",
            name="ck_process_observations_file_operations_non_negative",
        ),
        Index("ix_process_observations_pid", "pid"),
        Index("ix_process_observations_process_name", "process_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scan_runs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    process_started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    cpu_usage_percent: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    memory_usage_percent: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    process_size_mb: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    memory_usage_mb: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    execution_time_sec: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    thread_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    network_connections: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    bytes_sent_mb: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    failed_accesses: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    file_operations: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_anomalous: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    # Relationships
    scan_run: Mapped[ScanRun] = relationship(
        "ScanRun",
        back_populates="process_observations",
    )

    def __repr__(self) -> str:
        return (
            f"<ProcessObservation(id={self.id}, scan_id={self.scan_id}, "
            f"pid={self.pid}, process_name='{self.process_name}')>"
        )


class NetworkConnection(Base):
    """Represents an active network connection observed during a scan run."""

    __tablename__ = "network_connections"

    __table_args__ = (
        CheckConstraint(
            "source_port IS NULL OR (source_port >= 0 AND source_port <= 65535)",
            name="ck_network_connections_source_port_range",
        ),
        CheckConstraint(
            "destination_port IS NULL OR (destination_port >= 0 AND destination_port <= 65535)",
            name="ck_network_connections_destination_port_range",
        ),
        Index("ix_network_connections_scan_id", "scan_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scan_runs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)

    # Relationships
    scan_run: Mapped[ScanRun] = relationship(
        "ScanRun",
        back_populates="network_connections",
    )

    def __repr__(self) -> str:
        return (
            f"<NetworkConnection(id={self.id}, scan_id={self.scan_id}, "
            f"pid={self.pid}, status='{self.status}')>"
        )


class SecurityEvent(Base):
    """Represents a discrete security event or anomaly detected on a host."""

    __tablename__ = "security_events"

    __table_args__ = (
        UniqueConstraint(
            "deduplication_key",
            name="uq_security_events_deduplication_key",
        ),
        CheckConstraint(
            "severity IS NULL OR severity IN ('low', 'medium', 'high')",
            name="ck_security_events_severity_valid",
        ),
        Index("ix_security_events_host_id_occurred_at", "host_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("hosts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scan_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("scan_runs.id", ondelete="RESTRICT"),
        nullable=True,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    deduplication_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Relationships
    host: Mapped[Host] = relationship(
        "Host",
        back_populates="security_events",
    )
    scan_run: Mapped[Optional[ScanRun]] = relationship(
        "ScanRun",
        back_populates="security_events",
    )
    response_actions: Mapped[List[ResponseAction]] = relationship(
        "ResponseAction",
        back_populates="security_event",
        passive_deletes="all",
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityEvent(id={self.id}, host_id={self.host_id}, "
            f"event_type='{self.event_type}', severity='{self.severity}')>"
        )


class ResponseAction(Base):
    """Represents an automated or admin-approved mitigation action taken for an event."""

    __tablename__ = "response_actions"

    __table_args__ = (
        CheckConstraint(
            "action IN ('none', 'alert_only', 'lower_priority', 'terminate_process', 'block_ip')",
            name="ck_response_actions_action_valid",
        ),
        CheckConstraint(
            "severity IS NULL OR severity IN ('low', 'medium', 'high')",
            name="ck_response_actions_severity_valid",
        ),
        Index(
            "ix_response_actions_security_event_id_created_at",
            "security_event_id",
            "created_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    security_event_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("security_events.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    needs_admin_approval: Mapped[bool] = mapped_column(Boolean, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(100), nullable=False)
    executed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships
    security_event: Mapped[SecurityEvent] = relationship(
        "SecurityEvent",
        back_populates="response_actions",
    )

    def __repr__(self) -> str:
        return (
            f"<ResponseAction(id={self.id}, security_event_id={self.security_event_id}, "
            f"action='{self.action}', executed={self.executed})>"
        )
