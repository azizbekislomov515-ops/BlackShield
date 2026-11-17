import json
from pathlib import Path

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.db.models import Signature
from app.ingest.local_feed import default_source, import_feed
from tests.conftest import T0, publish, sha256_of


def stored(engine: Engine) -> dict[str, Signature]:
    with Session(engine) as db:
        return {s.hash: s for s in db.scalars(select(Signature))}


def test_csv_feed(engine: Engine, tmp_path: Path) -> None:
    feed = tmp_path / "Partner Feed.csv"
    feed.write_text(
        "\ufeffHash,Algorithm,Family,Severity,First_Seen\n"
        f"{sha256_of(1).upper()},SHA-256,Joker,critical,2026-02-03T04:05:06Z\n"
        f"{'ab' * 16},,,,\n"
        f"{sha256_of(1)},sha256,Dupe,low,2026-05-01T00:00:00Z\n"
        "not-a-hash,,,,\n"
        f"{'ab' * 16},sha256,,,\n",
        encoding="utf-8",
    )

    with Session(engine) as db:
        report = import_feed(db, feed, now=T0)

    assert report.records == 5
    assert report.rejected == 2
    assert report.errors[0].startswith("line 5:")
    assert (report.result.added, report.result.unchanged) == (2, 1)
    rows = stored(engine)
    joker = rows[sha256_of(1)]
    assert (joker.family, joker.severity, joker.source) == (
        "Joker",
        "critical",
        "local:partner-feed",
    )
    assert joker.first_seen.isoformat() == "2026-02-03T04:05:06+00:00"
    md5 = rows["ab" * 16]
    assert (md5.algorithm, md5.severity, md5.first_seen) == ("md5", "high", T0)


def test_ndjson_feed_with_removals(engine: Engine, tmp_path: Path) -> None:
    publish(engine, add=[sha256_of(1), sha256_of(2)])
    feed = tmp_path / "feed.ndjson"
    lines = [
        {"hash": sha256_of(3), "family": "Anatsa", "severity": "medium"},
        {"hash": sha256_of(1), "action": "remove"},
        {"hash": sha256_of(4), "action": "explode"},
        [1, 2],
    ]
    feed.write_text("\n".join(json.dumps(x) for x in lines) + "\n\n{broken\n", encoding="utf-8")

    with Session(engine) as db:
        report = import_feed(db, feed, source="local:test", default_severity="low", now=T0)

    assert report.rejected == 3
    assert (report.result.version, report.result.added, report.result.removed) == (2, 1, 1)
    rows = stored(engine)
    assert rows[sha256_of(1)].removed is True
    assert rows[sha256_of(3)].severity == "medium"
    assert rows[sha256_of(3)].source == "local:test"


def test_json_array_feed(engine: Engine, tmp_path: Path) -> None:
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps([{"hash": sha256_of(1)}, {"hash": sha256_of(2), "family": 5}]))

    with Session(engine) as db:
        report = import_feed(db, feed, now=T0)

    assert (report.result.added, report.rejected) == (1, 1)


def test_json_feed_must_be_an_array(engine: Engine, tmp_path: Path) -> None:
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"hash": sha256_of(1)}))

    with Session(engine) as db, pytest.raises(ValueError, match="array"):
        import_feed(db, feed)


def test_csv_without_hash_column_is_rejected(engine: Engine, tmp_path: Path) -> None:
    feed = tmp_path / "feed.csv"
    feed.write_text("sha,family\nabc,x\n")

    with Session(engine) as db, pytest.raises(ValueError, match="hash"):
        import_feed(db, feed)


def test_unknown_extension_needs_format(engine: Engine, tmp_path: Path) -> None:
    feed = tmp_path / "feed.txt"
    feed.write_text(f"hash\n{sha256_of(1)}\n")

    with Session(engine) as db:
        with pytest.raises(ValueError, match="--format"):
            import_feed(db, feed)
        assert import_feed(db, feed, fmt="csv").result.added == 1


def test_default_source_is_sanitized() -> None:
    assert default_source(Path("My Feed (v2).csv")) == "local:my-feed--v2-"
