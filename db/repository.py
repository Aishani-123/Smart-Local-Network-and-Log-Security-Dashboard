"""
db.repository – Data-access functions for Host lookup and upsert.

All functions accept an existing :class:`~sqlalchemy.orm.Session` and
**never** commit, roll back, or close it.  Transaction boundaries are
the caller's responsibility.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import Host


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def get_host_by_hostname(session: Session, hostname: str) -> Host | None:
    """Return the :class:`Host` matching *hostname*, or ``None``.

    Parameters
    ----------
    session:
        An open SQLAlchemy session (caller-managed).
    hostname:
        The exact hostname to search for (case-sensitive).

    Raises
    ------
    ValueError
        If *hostname* is empty or contains only whitespace.
    """
    if not hostname or not hostname.strip():
        raise ValueError("hostname must not be empty or whitespace")

    stmt = select(Host).where(Host.hostname == hostname.strip())
    return session.execute(stmt).scalars().first()


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------


def get_or_create_host(
    session: Session,
    hostname: str,
    operating_system: str | None = None,
) -> Host:
    """Insert a new host or update the existing one atomically.

    Uses PostgreSQL ``INSERT … ON CONFLICT DO UPDATE`` so the
    operation is safe under concurrent access without application-level
    locking.

    **Insert path** – a new row is created with *hostname* (and
    optionally *operating_system*); ``first_seen_at`` and
    ``last_seen_at`` receive database-side ``now()`` via their
    ``server_default``.

    **Conflict path** – ``last_seen_at`` is always refreshed to
    ``now()``.  If a non-empty *operating_system* is supplied it
    overwrites the stored value; otherwise the existing value is
    preserved.

    Parameters
    ----------
    session:
        An open SQLAlchemy session (caller-managed).
    hostname:
        Hostname string; leading/trailing whitespace is stripped.
    operating_system:
        Optional OS identifier.  ``None`` and empty strings are
        treated as "no value" and will **not** overwrite an existing
        OS entry.

    Returns
    -------
    Host
        The resulting ORM instance, including its database-generated
        ``id`` and timestamps.

    Raises
    ------
    ValueError
        If *hostname* is empty or contains only whitespace.

    Notes
    -----
    This function calls :meth:`~sqlalchemy.orm.Session.flush` before
    executing the upsert so that any pending ORM mutations are written
    to the database within the current transaction.  This prevents
    silent data loss when an identity-mapped Host carries unflushed
    attribute changes.  The caller's transaction is **not** committed.
    """
    hostname = hostname.strip() if hostname else ""
    if not hostname:
        raise ValueError("hostname must not be empty or whitespace")

    # Normalize: treat empty string the same as None.
    if operating_system is not None:
        operating_system = operating_system.strip() or None

    # ------------------------------------------------------------------
    # Build the INSERT … ON CONFLICT DO UPDATE statement.
    # ------------------------------------------------------------------
    insert_values: dict = {"hostname": hostname}
    if operating_system is not None:
        insert_values["operating_system"] = operating_system

    stmt = pg_insert(Host).values(**insert_values)

    # SET clause executed when the hostname already exists.
    update_set: dict = {"last_seen_at": func.now()}

    if operating_system is not None:
        # Caller supplied a meaningful OS value → overwrite.
        update_set["operating_system"] = operating_system
    # When operating_system is None we intentionally omit it from the
    # SET clause so the existing stored value is preserved unchanged.

    stmt = stmt.on_conflict_do_update(
        index_elements=["hostname"],
        set_=update_set,
    )

    # RETURNING lets us get the full row back in one round-trip.
    stmt = stmt.returning(Host)

    # Flush any pending ORM state so that in-memory attribute changes
    # are persisted before the upsert runs.  Without this flush,
    # populate_existing would silently overwrite unflushed mutations
    # on an identity-mapped Host.  This mirrors the behaviour of
    # autoflush=True (which this project disables).  The caller's
    # transaction is NOT committed — only a flush (write) occurs.
    session.flush()

    # Execute via the ORM to get a mapped Host instance.
    # from_statement() maps the RETURNING columns onto the Host entity.
    # populate_existing overwrites stale identity-map attributes with
    # the fresh RETURNING data in a single round-trip (no lazy load).
    orm_stmt = (
        select(Host)
        .from_statement(stmt)
        .execution_options(populate_existing=True)
    )
    host: Host = session.execute(orm_stmt).scalars().first()  # type: ignore[assignment]

    return host
