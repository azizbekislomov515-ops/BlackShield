"""End to end over real HTTP: uvicorn serving the app, the example client syncing from it."""

import importlib.util
import socket
import sqlite3
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType

import pytest
import uvicorn
from fastapi import FastAPI
from sqlalchemy import Engine

from tests.conftest import API_KEY, publish, sha256_of

CLIENT_PATH = Path(__file__).resolve().parents[1] / "examples" / "sync_client.py"


def load_client() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sync_client", CLIENT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def server(app_factory: Callable[..., FastAPI]) -> Iterator[str]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(app_factory(), log_config=None, lifespan="off")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    while not srv.started:
        thread.join(0.01)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(5)
    sock.close()


def local_hashes(db: sqlite3.Connection) -> set[str]:
    return {row[0] for row in db.execute("SELECT hash FROM signatures")}


def test_full_then_delta_sync_and_lookup(server: str, engine: Engine, tmp_path: Path) -> None:
    client = load_client()
    api = client.Api(server, API_KEY)
    db = client.open_store(str(tmp_path / "local.db"))
    publish(engine, add=[sha256_of(i) for i in range(25)])

    first = client.sync(api, db)
    assert first == {"mode": "full", "version": 1, "signatures": 25}

    publish(engine, add=[sha256_of(100)], remove=[sha256_of(0), sha256_of(1)])
    publish(engine, add=[sha256_of(101)])
    second = client.sync(api, db)
    assert second == {"mode": "delta", "version": 3, "added": 2, "removed": 2}
    assert local_hashes(db) == {sha256_of(i) for i in [*range(2, 25), 100, 101]}

    assert client.sync(api, db) == {"mode": "none", "version": 3}

    verdicts = client.lookup(api, [sha256_of(100), sha256_of(0)])
    assert [v["verdict"] for v in verdicts] == ["malicious", "unknown"]


def test_client_resyncs_when_ahead_of_server(server: str, engine: Engine, tmp_path: Path) -> None:
    client = load_client()
    api = client.Api(server, API_KEY)
    db = client.open_store(str(tmp_path / "local.db"))
    publish(engine, add=[sha256_of(1)])
    client.set_version(db, 7)  # e.g. the server database was rebuilt

    assert client.sync(api, db)["mode"] == "full"
    assert local_hashes(db) == {sha256_of(1)}


def test_client_refuses_plain_http_to_remote_hosts() -> None:
    client = load_client()

    with pytest.raises(client.SyncError):
        client.Api("http://api.example.com", API_KEY)
