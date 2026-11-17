"""Signature storage: versioned writes, delta pages, streamed snapshots and lookups.

Write model: every successful import is one database transaction that allocates the next
version number, stamps every row it changes with that version and records the active count in
``signature_versions``. A transaction that changes nothing is rolled back and allocates nothing.
"""

import logging
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import islice
from typing import Any

from sqlalchemy import Engine, Row, and_, func, insert, or_, select, text, update
from sqlalchemy.orm import Session

from app.db.models import Signature, SignatureVersion
from app.signatures.normalize import Removal, SignatureRecord

logger = logging.getLogger(__name__)

# pg_advisory_xact_lock key that serializes signature writers ("BLKS").
WRITER_LOCK_ID = 0x424C4B53
DEFAULT_BATCH_SIZE = 2_000
SNAPSHOT_FETCH_ROWS = 5_000


@dataclass
class ApplyResult:
    """Outcome of one import. ``version`` is None when nothing changed."""

    version: int | None = None
    added: int = 0
    resurrected: int = 0
    removed: int = 0
    unchanged: int = 0
    active_count: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def changed(self) -> int:
        return self.added + self.resurrected + self.removed


def latest_version(session: Session) -> SignatureVersion | None:
    return session.scalars(
        select(SignatureVersion).order_by(SignatureVersion.version.desc()).limit(1)
    ).first()


def apply_changes(
    session: Session,
    changes: Iterable[SignatureRecord | Removal],
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    now: datetime | None = None,
) -> ApplyResult:
    """Apply additions and removals as one new signature version.

    ``changes`` may be a lazy iterator (a large feed file); it is consumed in batches. When one
    call both adds and removes a hash, the last change in feed order wins. Concurrent writers are
    serialized (advisory lock on PostgreSQL; the version primary key catches anything else), so
    versions are committed in order and a reader never sees version N+1 before version N.
    """
    if session.in_transaction():
        raise RuntimeError("apply_changes needs a session without an open transaction")
    created_at = now or datetime.now(UTC)
    result = ApplyResult()
    session.begin()
    try:
        if session.get_bind().dialect.name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": WRITER_LOCK_ID})
        previous = session.scalar(select(func.max(SignatureVersion.version))) or 0
        version = previous + 1
        session.add(SignatureVersion(version=version, created_at=created_at, count=0))
        session.flush()

        iterator = iter(changes)
        while batch := list(islice(iterator, batch_size)):
            additions: dict[str, SignatureRecord] = {}
            removals: set[str] = set()
            # Fold the batch to one change per hash, the last in feed order. Batches are then
            # applied in order, so the outcome does not depend on where batch boundaries fall.
            for change in batch:
                if isinstance(change, Removal):
                    additions.pop(change.hash, None)
                    removals.add(change.hash)
                else:
                    removals.discard(change.hash)
                    if change.hash in additions:
                        result.unchanged += 1  # duplicate within the batch
                    _merge_addition(additions, change)
            if additions:
                _apply_additions(session, additions, version, result)
            if removals:
                result.removed += _apply_removals(session, removals, version)

        if result.changed == 0:
            session.rollback()
            current = latest_version(session)
            result.active_count = current.count if current else 0
            session.rollback()
            return result

        result.active_count = session.scalar(
            select(func.count()).select_from(Signature).where(Signature.removed.is_(False))
        )
        session.execute(
            update(SignatureVersion)
            .where(SignatureVersion.version == version)
            .values(count=result.active_count)
        )
        session.commit()
    except BaseException:
        session.rollback()
        raise
    result.version = version
    logger.info(
        "signature version published",
        extra={
            "version": version,
            "added": result.added,
            "resurrected": result.resurrected,
            "removed": result.removed,
            "unchanged": result.unchanged,
            "active_count": result.active_count,
        },
    )
    return result


def _merge_addition(additions: dict[str, SignatureRecord], record: SignatureRecord) -> None:
    """Deduplicate within a batch: the first record wins, keeping the earliest first_seen."""
    existing = additions.get(record.hash)
    if existing is None:
        additions[record.hash] = record
    elif record.first_seen < existing.first_seen:
        additions[record.hash] = SignatureRecord(
            hash=existing.hash,
            algorithm=existing.algorithm,
            family=existing.family or record.family,
            severity=existing.severity,
            source=existing.source,
            first_seen=record.first_seen,
        )


def _apply_additions(
    session: Session, additions: dict[str, SignatureRecord], version: int, result: ApplyResult
) -> None:
    rows = session.execute(
        select(Signature.hash, Signature.removed, Signature.first_seen).where(
            Signature.hash.in_(additions.keys())
        )
    ).all()
    existing = {row.hash: row for row in rows}

    inserts: list[dict[str, Any]] = []
    resurrects: list[dict[str, Any]] = []
    for digest, record in additions.items():
        row = existing.get(digest)
        if row is None:
            inserts.append(_row(record, version, record.first_seen))
        elif row.removed:
            resurrects.append(_row(record, version, min(row.first_seen, record.first_seen)))
        else:
            # Already active: the first source wins. Nothing to publish.
            result.unchanged += 1
    if inserts:
        session.execute(insert(Signature), inserts)
    if resurrects:
        session.execute(update(Signature), resurrects)
    result.added += len(inserts)
    result.resurrected += len(resurrects)


def _row(record: SignatureRecord, version: int, first_seen: datetime) -> dict[str, Any]:
    return {
        "hash": record.hash,
        "algorithm": record.algorithm,
        "family": record.family,
        "source": record.source,
        "severity": record.severity,
        "first_seen": first_seen,
        "version": version,
        "removed": False,
    }


def _apply_removals(session: Session, hashes: set[str], version: int) -> int:
    outcome = session.execute(
        update(Signature)
        .where(Signature.hash.in_(hashes), Signature.removed.is_(False))
        .values(removed=True, version=version)
        .execution_options(synchronize_session=False)
    )
    return outcome.rowcount  # type: ignore[attr-defined]


# --- Reads -----------------------------------------------------------------------------------

_DELTA_COLUMNS = (
    Signature.hash,
    Signature.algorithm,
    Signature.family,
    Signature.severity,
    Signature.version,
    Signature.removed,
)


def delta_page(
    session: Session,
    *,
    since: int,
    until: int,
    after: tuple[int, str] | None,
    limit: int,
) -> Sequence[Row[Any]]:
    """Rows changed in versions (since, until], ordered by (version, hash), after a keyset."""
    query = select(*_DELTA_COLUMNS).where(Signature.version > since, Signature.version <= until)
    if after is not None:
        after_version, after_hash = after
        query = query.where(
            or_(
                Signature.version > after_version,
                and_(Signature.version == after_version, Signature.hash > after_hash),
            )
        )
    return session.execute(query.order_by(Signature.version, Signature.hash).limit(limit)).all()


@dataclass(frozen=True)
class SnapshotHeader:
    version: int
    count: int
    created_at: datetime | None


def iter_snapshot(
    engine: Engine, *, fetch_rows: int = SNAPSHOT_FETCH_ROWS
) -> Iterator[SnapshotHeader | Row[Any]]:
    """Yield a header, then every active signature ordered by hash, from one consistent snapshot.

    Rows are fetched ``fetch_rows`` at a time through a server-side cursor (PostgreSQL) or an
    incremental SQLite cursor, so memory use does not grow with the table. The header and rows
    come from a single REPEATABLE READ transaction, so writes committed during the stream are
    not mixed in.
    """
    with engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            connection = connection.execution_options(
                isolation_level="REPEATABLE READ", postgresql_readonly=True
            )
        with connection.begin():
            latest = connection.execute(
                select(
                    SignatureVersion.version, SignatureVersion.count, SignatureVersion.created_at
                )
                .order_by(SignatureVersion.version.desc())
                .limit(1)
            ).first()
            yield SnapshotHeader(
                version=latest.version if latest else 0,
                count=latest.count if latest else 0,
                created_at=latest.created_at if latest else None,
            )
            rows = connection.execution_options(yield_per=fetch_rows).execute(
                select(Signature.hash, Signature.algorithm, Signature.family, Signature.severity)
                .where(Signature.removed.is_(False))
                .order_by(Signature.hash)
            )
            yield from rows


def lookup_sha256(session: Session, hashes: Sequence[str]) -> dict[str, Row[Any]]:
    """Active SHA-256 signatures among ``hashes`` (already normalized), keyed by hash."""
    if not hashes:
        return {}
    rows = session.execute(
        select(Signature.hash, Signature.family, Signature.severity).where(
            Signature.hash.in_(hashes),
            Signature.algorithm == "sha256",
            Signature.removed.is_(False),
        )
    ).all()
    return {row.hash: row for row in rows}
