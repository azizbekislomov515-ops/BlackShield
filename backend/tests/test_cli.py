import json
import threading
from pathlib import Path

import pytest
from sqlalchemy import Engine

from app.cli import main
from app.core.security import ApiKeyRing
from app.ingest.scheduler import run_periodically
from tests.conftest import publish, sha256_of


def last_json(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    return json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_import_feed_status_and_remove(
    engine: Engine, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    feed = tmp_path / "feed.csv"
    feed.write_text(f"hash,family\n{sha256_of(1)},Joker\n{sha256_of(2)},Joker\n")

    assert main(["import-feed", str(feed), "--source", "local:cli"], engine=engine) == 0
    assert last_json(capsys)["added"] == 2

    assert main(["remove", sha256_of(1).upper()], engine=engine) == 0
    assert last_json(capsys) == {"version": 2, "removed": 1}

    assert main(["status"], engine=engine) == 0
    status = last_json(capsys)
    assert (status["version"], status["count"]) == (2, 1)


def test_remove_rejects_invalid_hash(engine: Engine) -> None:
    assert main(["remove", "xyz"], engine=engine) == 1


def test_import_missing_file_fails(engine: Engine, tmp_path: Path) -> None:
    assert main(["import-feed", str(tmp_path / "missing.csv")], engine=engine) == 1


def test_ingest_without_api_key_fails(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)
    from app.core.config import get_settings

    get_settings.cache_clear()
    try:
        monkeypatch.chdir(Path(__file__).parent)  # no .env here
        assert main(["ingest-malwarebazaar"], engine=engine) == 1
    finally:
        get_settings.cache_clear()


def test_generate_api_key_output_verifies(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate-api-key", "--id", "android-v1"]) == 0
    lines = [line.strip() for line in capsys.readouterr().out.splitlines()]
    key, entry = lines[1], lines[3]

    assert key.startswith("bs_")
    assert entry.startswith("android-v1:")
    assert ApiKeyRing.parse(entry).verify(key) == "android-v1"


def test_scheduler_survives_failures_and_stops() -> None:
    calls: list[int] = []
    stop = threading.Event()

    def job() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("transient")
        if len(calls) == 3:
            stop.set()

    runs = run_periodically(job, interval=0.001, stop=stop)

    assert runs == 3


def test_scheduler_max_runs(engine: Engine) -> None:
    publish(engine, add=[sha256_of(1)])
    assert run_periodically(lambda: None, interval=0.001, max_runs=2) == 2
