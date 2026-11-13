"""Versioned domain storage: the signature write model (app/signatures/store.py) for domains.

Every successful import is one transaction that allocates the next version, stamps each row it
changes with that version and records the active count. A transaction that changes nothing is
rolled back and allocates nothing. Removed domains stay as tombstones for deltas.
"""

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import islice
from typing import Any

from sqlalchemy import Row, and_, func, insert, or_, select, text, update
from sqlalchemy.orm import Session

from app.db.models import BlockedDomain, DomainVersion
from app.domains.normalize import DomainRecord, DomainRemoval

logger = logging.getLogger(__name__)

# pg_advisory_xact_lock key that serializes domain writers ("BLKD").
WRITER_LOCK_ID = 0x424C4B44
BATCH_SIZE = 2_000


@dataclass
class DomainApplyResult:
    """Outcome of one import. ``version`` is None when nothing changed."""

    version: int | None = None
    added: int = 0
    resurrected: int = 0
    removed: int = 0
    unchanged: int = 0
    active_count: int = 0

    @property
    def changed(self) -> int:
        return self.added + self.resurrected + self.removed


def latest_domain_version(session: Session) -> DomainVersion | None:
    return session.scalars(
        select(DomainVersion).order_by(DomainVersion.version.desc()).limit(1)
    ).first()


def apply_domain_changes(
    session: Session,
    changes: Iterable[DomainRecord | DomainRemoval],
    *,
    now: datetime | None = None,
) -> DomainApplyResult:
    """Apply additions and removals as one new version; the last change per domain wins."""
    if session.in_transaction():
        raise RuntimeError("apply_domain_changes needs a session without an open transaction")
    result = DomainApplyResult()
    session.begin()
    try:
        if session.get_bind().dialect.name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": WRITER_LOCK_ID})
        version = (session.scalar(select(func.max(DomainVersion.version))) or 0) + 1
        session.add(DomainVersion(version=version, created_at=now or datetime.now(UTC), count=0))
        session.flush()

        iterator = iter(changes)
        while batch := list(islice(iterator, BATCH_SIZE)):
            additions: dict[str, DomainRecord] = {}
            removals: set[str] = set()
            for change in batch:
                if isinstance(change, DomainRemoval):
                    additions.pop(change.domain, None)
                    removals.add(change.domain)
                else:
                    removals.discard(change.domain)
                    if change.domain in additions:
                        result.unchanged += 1
                    else:
                        additions[change.domain] = change
            if additions:
                _add(session, additions, version, result)
            if removals:
                result.removed += _remove(session, removals, version)

        if result.changed == 0:
            session.rollback()
            current = latest_domain_version(session)
            result.active_count = current.count if current else 0
            session.rollback()
            return result
        result.active_count = _active_count(session)
        session.execute(
            update(DomainVersion)
            .where(DomainVersion.version == version)
            .values(count=result.active_count)
        )
        session.commit()
    except BaseException:
        session.rollback()
        raise
    result.version = version
    logger.info(
        "domain version published",
        extra={
            "version": version,
            "added": result.added,
            "resurrected": result.resurrected,
            "removed": result.removed,
            "active_count": result.active_count,
        },
    )
    return result


def replace_source(
    session: Session, source: str, records: Iterable[DomainRecord], *, now: datetime | None = None
) -> DomainApplyResult:
    """Make ``source``'s active domains exactly ``records`` (a feed's complete current list).

    Domains the feed no longer lists are removed, but only if this source added them: a domain
    listed by two feeds stays until the feed that owns the row drops it.
    """
    wanted = {record.domain: record for record in records}
    owned = set(
        session.scalars(
            select(BlockedDomain.domain).where(
                BlockedDomain.source == source, BlockedDomain.removed.is_(False)
            )
        )
    )
    session.rollback()  # end the read transaction before the write transaction
    changes: list[DomainRecord | DomainRemoval] = [
        DomainRemoval(domain) for domain in sorted(owned - wanted.keys())
    ]
    changes += [wanted[domain] for domain in sorted(wanted)]
    return apply_domain_changes(session, changes, now=now)


def _add(
    session: Session, additions: dict[str, DomainRecord], version: int, result: DomainApplyResult
) -> None:
    existing = {
        row.domain: row
        for row in session.execute(
            select(BlockedDomain.domain, BlockedDomain.removed, BlockedDomain.first_seen).where(
                BlockedDomain.domain.in_(additions.keys())
            )
        )
    }
    inserts: list[dict[str, Any]] = []
    resurrects: list[dict[str, Any]] = []
    for domain, record in additions.items():
        row = existing.get(domain)
        if row is None:
            inserts.append(_row(record, version, record.first_seen))
        elif row.removed:
            resurrects.append(_row(record, version, min(row.first_seen, record.first_seen)))
        else:
            result.unchanged += 1  # already active; the first source keeps it
    if inserts:
        session.execute(insert(BlockedDomain), inserts)
    if resurrects:
        session.execute(update(BlockedDomain), resurrects)
    result.added += len(inserts)
    result.resurrected += len(resurrects)


def _row(record: DomainRecord, version: int, first_seen: datetime) -> dict[str, Any]:
    return {
        "domain": record.domain,
        "category": record.category,
        "source": record.source,
        "first_seen": first_seen,
        "version": version,
        "removed": False,
    }


def _remove(session: Session, domains: set[str], version: int) -> int:
    outcome = session.execute(
        update(BlockedDomain)
        .where(BlockedDomain.domain.in_(domains), BlockedDomain.removed.is_(False))
        .values(removed=True, version=version)
        .execution_options(synchronize_session=False)
    )
    return outcome.rowcount  # type: ignore[attr-defined]


def _active_count(session: Session) -> int:
    return (
        session.scalar(
            select(func.count()).select_from(BlockedDomain).where(BlockedDomain.removed.is_(False))
        )
        or 0
    )


def domain_delta_page(
    session: Session, *, since: int, until: int, after: tuple[int, str] | None, limit: int
) -> Sequence[Row[Any]]:
    """Rows changed in versions (since, until], ordered by (version, domain), after a keyset."""
    query = select(
        BlockedDomain.domain, BlockedDomain.category, BlockedDomain.version, BlockedDomain.removed
    ).where(BlockedDomain.version > since, BlockedDomain.version <= until)
    if after is not None:
        after_version, after_domain = after
        query = query.where(
            or_(
                BlockedDomain.version > after_version,
                and_(BlockedDomain.version == after_version, BlockedDomain.domain > after_domain),
            )
        )
    return session.execute(
        query.order_by(BlockedDomain.version, BlockedDomain.domain).limit(limit)
    ).all()
