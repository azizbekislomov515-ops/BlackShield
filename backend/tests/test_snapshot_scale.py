"""Acceptance: a 500k-row snapshot streams without loading everything in memory."""

import json
import tracemalloc
import zlib
from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine, event, insert
from sqlalchemy.orm import Session

from app.api.v1.signatures import gzip_chunks, snapshot_ndjson
from app.db.models import Signature, SignatureVersion
from tests.conftest import sha256_of

ROWS = 500_000
INSERT_CHUNK = 50_000
# Holding 500k rows as Python objects takes hundreds of MB; a streaming encoder needs a few MB.
PEAK_LIMIT_BYTES = 32 * 1024 * 1024


def populate(engine: Engine) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with Session(engine) as db, db.begin():
        db.add(SignatureVersion(version=1, created_at=now, count=ROWS))
        db.flush()
        for start in range(0, ROWS, INSERT_CHUNK):
            db.execute(
                insert(Signature),
                [
                    {
                        "hash": sha256_of(n * 2654435761 % 2**64),  # not inserted in hash order
                        "algorithm": "sha256",
                        "family": "Family" + str(n % 97),
                        "source": "scale-test",
                        "severity": "high",
                        "first_seen": now,
                        "version": 1,
                        "removed": False,
                    }
                    for n in range(start, start + INSERT_CHUNK)
                ],
            )


def test_500k_snapshot_streams_in_bounded_memory(engine: Engine) -> None:
    populate(engine)

    decompressor = zlib.decompressobj(wbits=31)
    lines = 0
    tail = b""
    first_line = b""
    previous_hash = ""
    chunks = 0

    tracemalloc.start()
    try:
        for chunk in gzip_chunks(snapshot_ndjson(engine)):
            chunks += 1
            data = tail + decompressor.decompress(chunk)
            *complete, tail = data.split(b"\n")
            for line in complete:
                if not first_line:
                    first_line = line
                elif line.startswith(b'{"hash"'):
                    current = line[9:73].decode()
                    assert current > previous_hash  # ordered by hash, no duplicates
                    previous_hash = current
                lines += 1
                last_line = line
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert tail == b""
    assert lines == ROWS + 2
    assert json.loads(first_line)["count"] == ROWS
    assert json.loads(last_line) == {"type": "end", "version": 1, "count": ROWS}
    assert chunks > 100  # really streamed, not produced as one blob
    assert peak < PEAK_LIMIT_BYTES, f"peak traced memory {peak / 2**20:.1f} MiB"


def test_snapshot_uses_a_server_side_cursor_on_postgresql(engine: Engine) -> None:
    """tracemalloc cannot see libpq's buffers, so check the cursor type directly."""
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL only")
    cursors: dict[str, str] = {}

    def record_cursor(conn, cursor, statement, parameters, context, executemany) -> None:
        if "FROM signatures" in statement:
            cursors[statement] = type(cursor).__name__

    event.listen(engine, "before_cursor_execute", record_cursor)
    try:
        list(snapshot_ndjson(engine))
    finally:
        event.remove(engine, "before_cursor_execute", record_cursor)

    assert list(cursors.values()) == ["ServerCursor"]
