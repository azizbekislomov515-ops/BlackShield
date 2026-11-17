from datetime import timedelta

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.db.models import Base, Signature, SignatureVersion
from app.signatures.normalize import Removal
from app.signatures.store import apply_changes, latest_version, lookup_sha256
from tests.conftest import T0, alembic_config, publish, record, sha256_of


def rows(engine: Engine) -> dict[str, Signature]:
    with Session(engine) as db:
        return {s.hash: s for s in db.scalars(select(Signature))}


def test_migrations_match_models(engine: Engine) -> None:
    with engine.connect() as connection:
        diff = compare_metadata(MigrationContext.configure(connection), Base.metadata)

    assert diff == []


def test_migration_downgrade_and_upgrade_round_trip(database_url: str, engine: Engine) -> None:
    config = alembic_config(database_url)
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    assert publish(engine, add=[sha256_of(1)]).version == 1


def test_first_import_creates_version_1(engine: Engine) -> None:
    result = publish(engine, add=[sha256_of(1), sha256_of(2)])

    assert result.version == 1
    assert (result.added, result.removed, result.active_count) == (2, 0, 2)
    with Session(engine) as db:
        latest = latest_version(db)
    assert latest is not None
    assert (latest.version, latest.count) == (1, 2)
    assert latest.created_at.tzinfo is not None
    assert {r.version for r in rows(engine).values()} == {1}


def test_duplicates_within_a_batch_are_merged(engine: Engine) -> None:
    digest = sha256_of(7)
    with Session(engine) as db:
        result = apply_changes(
            db,
            [
                record(digest, family=None, first_seen=T0 + timedelta(days=2)),
                record(digest, family="Hydra", first_seen=T0),
            ],
        )

    assert result.added == 1
    stored = rows(engine)[digest]
    assert stored.first_seen == T0
    assert stored.family == "Hydra"


def test_reimport_without_changes_publishes_nothing(engine: Engine) -> None:
    publish(engine, add=[sha256_of(1)])

    again = publish(engine, add=[sha256_of(1)])

    assert again.version is None
    assert (again.unchanged, again.active_count) == (1, 1)
    with Session(engine) as db:
        assert db.scalar(select(SignatureVersion.version).order_by(SignatureVersion.version.desc()))
        assert len(db.scalars(select(SignatureVersion)).all()) == 1


def test_duplicates_across_batches_are_unchanged(engine: Engine) -> None:
    hashes = [sha256_of(i % 5) for i in range(20)]
    with Session(engine) as db:
        result = apply_changes(db, [record(h) for h in hashes], batch_size=3)

    assert (result.added, result.unchanged, result.active_count) == (5, 15, 5)


def test_removal_leaves_tombstone_with_new_version(engine: Engine) -> None:
    publish(engine, add=[sha256_of(1), sha256_of(2)])

    result = publish(engine, remove=[sha256_of(1), sha256_of(99)])

    assert (result.version, result.removed, result.active_count) == (2, 1, 1)
    tombstone = rows(engine)[sha256_of(1)]
    assert (tombstone.removed, tombstone.version) == (True, 2)
    assert sha256_of(99) not in rows(engine)


def test_removing_unknown_hash_publishes_nothing(engine: Engine) -> None:
    publish(engine, add=[sha256_of(1)])

    assert publish(engine, remove=[sha256_of(2)]).version is None


def test_resurrection_bumps_version_and_keeps_first_seen(engine: Engine) -> None:
    digest = sha256_of(1)
    publish(engine, add=[digest])
    publish(engine, remove=[digest])

    with Session(engine) as db:
        result = apply_changes(db, [record(digest, family="New", first_seen=T0 + timedelta(9))])

    assert (result.version, result.resurrected, result.active_count) == (3, 1, 1)
    stored = rows(engine)[digest]
    assert (stored.removed, stored.version, stored.family, stored.first_seen) == (
        False,
        3,
        "New",
        T0,
    )


@pytest.mark.parametrize("batch_size", [1, 2, 2_000])
def test_add_then_remove_in_one_import_ends_inactive(engine: Engine, batch_size: int) -> None:
    digest = sha256_of(1)
    with Session(engine) as db:
        result = apply_changes(db, [record(digest), Removal(hash=digest)], batch_size=batch_size)

    assert result.active_count == 0
    stored = rows(engine).get(digest)
    assert stored is None or stored.removed is True


@pytest.mark.parametrize("batch_size", [1, 2, 2_000])
def test_remove_then_add_in_one_import_ends_active(engine: Engine, batch_size: int) -> None:
    """The last change in feed order wins, wherever the batch boundaries fall."""
    digest = sha256_of(1)
    publish(engine, add=[digest])
    with Session(engine) as db:
        result = apply_changes(db, [Removal(hash=digest), record(digest)], batch_size=batch_size)

    assert result.active_count == 1
    assert rows(engine)[digest].removed is False


@pytest.mark.parametrize("batch_size", [1, 3, 2_000])
def test_add_remove_add_in_one_import_ends_active(engine: Engine, batch_size: int) -> None:
    digest = sha256_of(1)
    changes = [record(digest), Removal(hash=digest), record(digest)]
    with Session(engine) as db:
        result = apply_changes(db, changes, batch_size=batch_size)

    assert result.active_count == 1
    assert rows(engine)[digest].removed is False


def test_failed_import_rolls_back_everything(engine: Engine) -> None:
    def changes():
        yield record(sha256_of(1))
        raise RuntimeError("feed broke")

    with Session(engine) as db, pytest.raises(RuntimeError):
        apply_changes(db, changes(), batch_size=1)

    assert rows(engine) == {}
    with Session(engine) as db:
        assert latest_version(db) is None


def test_lookup_returns_only_active_sha256(engine: Engine) -> None:
    md5 = "a" * 32
    with Session(engine) as db:
        apply_changes(
            db, [record(sha256_of(1)), record(sha256_of(2)), record(md5, algorithm="md5")]
        )
    publish(engine, remove=[sha256_of(2)])

    with Session(engine) as db:
        found = lookup_sha256(db, [sha256_of(1), sha256_of(2), sha256_of(3), md5])

    assert set(found) == {sha256_of(1)}
