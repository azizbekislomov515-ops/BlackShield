"""Concurrency guarantees that only PostgreSQL can exercise (SQLite has a single writer)."""

import json
import threading

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.api.v1.signatures import snapshot_ndjson
from app.db.models import SignatureVersion
from tests.conftest import publish, sha256_of


@pytest.fixture
def pg_engine(engine: Engine) -> Engine:
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL only (set TEST_DATABASE_URL)")
    return engine


def test_concurrent_writers_get_consecutive_versions(pg_engine: Engine) -> None:
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def writer(n: int) -> None:
        try:
            barrier.wait()
            publish(pg_engine, add=[sha256_of(1000 * n + i) for i in range(50)])
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    with Session(pg_engine) as db:
        versions = db.execute(
            select(SignatureVersion.version, SignatureVersion.count).order_by(
                SignatureVersion.version
            )
        ).all()
    # The advisory lock serializes writers: versions 1..8, each count 50 more than the last.
    assert [(v.version, v.count) for v in versions] == [(n, 50 * n) for n in range(1, 9)]


def test_snapshot_is_isolated_from_concurrent_writes(pg_engine: Engine) -> None:
    publish(pg_engine, add=[sha256_of(i) for i in range(3)])

    stream = snapshot_ndjson(pg_engine)
    first_chunk = next(stream)  # header sent, snapshot transaction open
    publish(pg_engine, add=[sha256_of(99)], remove=[sha256_of(0)])
    content = first_chunk + b"".join(stream)

    lines = [json.loads(line) for line in content.decode().splitlines()]
    assert lines[0]["version"] == 1
    assert [line["hash"] for line in lines[1:-1]] == [sha256_of(i) for i in range(3)]
    assert lines[-1] == {"type": "end", "version": 1, "count": 3}
