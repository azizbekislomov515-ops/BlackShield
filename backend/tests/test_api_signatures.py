import gzip
import json
import random
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.api.v1.signatures import encode_cursor
from app.db.models import Signature
from tests.conftest import publish, sha256_of

State = dict[str, tuple[str, str | None, str]]


def active_state(engine: Engine) -> State:
    with Session(engine) as db:
        rows = db.execute(
            select(Signature.hash, Signature.algorithm, Signature.family, Signature.severity).where(
                Signature.removed.is_(False)
            )
        ).all()
    return {r.hash: (r.algorithm, r.family, r.severity) for r in rows}


def sync_delta(client: TestClient, state: State, since: int, limit: int) -> tuple[State, int, int]:
    """Apply every delta page to a copy of ``state``. Returns (state, until, pages)."""
    state = dict(state)
    cursor: str | None = None
    pages = 0
    while True:
        params: dict[str, Any] = {"since": since, "limit": limit}
        if cursor:
            params["cursor"] = cursor
        response = client.get("/v1/signatures/delta", params=params)
        assert response.status_code == 200, response.text
        body = response.json()
        pages += 1
        assert len(body["additions"]) + len(body["removals"]) <= limit
        for item in body["additions"]:
            state[item["hash"]] = (item["algorithm"], item["family"], item["severity"])
        for item in body["removals"]:
            state.pop(item["hash"], None)
        cursor = body["next_cursor"]
        if cursor is None:
            return state, body["until"], pages


def test_version_is_zero_before_first_import(client: TestClient) -> None:
    response = client.get("/v1/signatures/version")

    assert response.status_code == 200
    assert response.json() == {"version": 0, "created_at": None, "count": 0}


def test_version_reports_latest(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1), sha256_of(2)])
    publish(engine, remove=[sha256_of(1)])

    body = client.get("/v1/signatures/version").json()

    assert (body["version"], body["count"]) == (2, 1)
    assert body["created_at"].startswith("2026-01-01T01:00:00")


def test_delta_is_gzip_compressed(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1)])

    response = client.get(
        "/v1/signatures/delta", params={"since": 0}, headers={"Accept-Encoding": "gzip"}
    )

    assert response.headers["content-encoding"] == "gzip"
    assert response.headers["vary"] == "Accept-Encoding"
    assert response.json()["additions"][0]["hash"] == sha256_of(1)  # transparently decoded


def test_delta_without_gzip_support_is_identity(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1)])

    response = client.get(
        "/v1/signatures/delta", params={"since": 0}, headers={"Accept-Encoding": "gzip;q=0"}
    )

    assert "content-encoding" not in response.headers
    assert json.loads(response.content)["until"] == 1


def test_delta_contents(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1), sha256_of(2), sha256_of(3)])  # v1
    publish(engine, remove=[sha256_of(2)])  # v2
    publish(engine, add=[sha256_of(4)], family=None)  # v3

    body = client.get("/v1/signatures/delta", params={"since": 1}).json()

    assert (body["since"], body["until"], body["latest_version"]) == (1, 3, 3)
    assert body["removals"] == [{"hash": sha256_of(2), "algorithm": "sha256", "version": 2}]
    assert body["additions"] == [
        {
            "hash": sha256_of(4),
            "algorithm": "sha256",
            "family": None,
            "severity": "high",
            "version": 3,
        }
    ]
    assert body["next_cursor"] is None


def test_delta_when_up_to_date_is_empty(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1)])

    body = client.get("/v1/signatures/delta", params={"since": 1}).json()

    assert (body["additions"], body["removals"], body["until"]) == ([], [], 1)


def test_delta_since_ahead_of_server_is_409(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1)])

    response = client.get("/v1/signatures/delta", params={"since": 5})

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "version_ahead"
    assert response.json()["detail"]["latest_version"] == 1


@pytest.mark.parametrize("params", [{"since": -1}, {"since": "x"}, {}, {"since": 0, "limit": 0}])
def test_delta_rejects_invalid_parameters(client: TestClient, params: dict[str, Any]) -> None:
    assert client.get("/v1/signatures/delta", params=params).status_code == 422


def test_delta_limit_is_capped(app_factory, engine: Engine) -> None:
    publish(engine, add=[sha256_of(i) for i in range(10)])
    with TestClient(app_factory(delta_max_limit=4), headers={"X-API-Key": _key()}) as client:
        body = client.get("/v1/signatures/delta", params={"since": 0, "limit": 1000}).json()

    assert len(body["additions"]) == 4
    assert body["next_cursor"] is not None


def _key() -> str:
    from tests.conftest import API_KEY

    return API_KEY


def test_pagination_returns_every_change_exactly_once(client: TestClient, engine: Engine) -> None:
    for start in range(0, 50, 10):
        publish(engine, add=[sha256_of(i) for i in range(start, start + 10)])
    publish(engine, remove=[sha256_of(i) for i in range(0, 50, 7)])

    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, Any] = {"since": 0, "limit": 7}
        if cursor:
            params["cursor"] = cursor
        body = client.get("/v1/signatures/delta", params=params).json()
        seen += [i["hash"] for i in body["additions"] + body["removals"]]
        cursor = body["next_cursor"]
        if not cursor:
            break

    assert len(seen) == len(set(seen)) == 50


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_delta_from_any_version_reaches_latest_state(
    client: TestClient, engine: Engine, seed: int
) -> None:
    """Skipping versions: from the state at every version v, one delta reaches the latest."""
    rng = random.Random(seed)
    universe = [sha256_of(i) for i in range(60)]
    snapshots: list[State] = [{}]
    for _ in range(15):
        active = list(active_state(engine))
        add = rng.sample(universe, rng.randint(0, 8))  # includes re-adds of removed hashes
        remove = rng.sample(active, min(len(active), rng.randint(0, 5)))
        result = publish(engine, add=add, remove=remove, family=f"F{rng.randint(1, 3)}")
        if result.version is not None:
            assert result.version == len(snapshots)
            snapshots.append(active_state(engine))
    latest = len(snapshots) - 1
    assert latest >= 10

    for since, state_at_since in enumerate(snapshots):
        state, until, _ = sync_delta(client, state_at_since, since, limit=rng.randint(1, 9))
        assert until == latest
        assert state == snapshots[latest], f"wrong state syncing from version {since}"


def test_write_between_pages_converges_on_next_sync(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(i) for i in range(6)])  # v1
    publish(engine, add=[sha256_of(i) for i in range(6, 12)])  # v2

    first = client.get("/v1/signatures/delta", params={"since": 0, "limit": 4}).json()
    state: State = {
        i["hash"]: (i["algorithm"], i["family"], i["severity"]) for i in first["additions"]
    }
    # v3 lands mid-sync: it removes a hash the client has not received yet and adds one.
    publish(engine, add=[sha256_of(100)], remove=[sha256_of(10)])

    cursor = first["next_cursor"]
    while cursor:
        body = client.get("/v1/signatures/delta", params={"since": 0, "cursor": cursor}).json()
        assert body["until"] == 2  # the sync finishes at the version it started at
        for item in body["additions"]:
            state[item["hash"]] = (item["algorithm"], item["family"], item["severity"])
        for item in body["removals"]:
            state.pop(item["hash"], None)
        cursor = body["next_cursor"]

    state, until, _ = sync_delta(client, state, 2, limit=4)
    assert until == 3
    assert state == active_state(engine)


def test_cursor_must_match_since(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(i) for i in range(5)])
    cursor = client.get("/v1/signatures/delta", params={"since": 0, "limit": 2}).json()[
        "next_cursor"
    ]

    response = client.get("/v1/signatures/delta", params={"since": 1, "cursor": cursor})

    assert response.status_code == 400


@pytest.mark.parametrize(
    "cursor",
    [
        "not-base64!",
        "eyJ9",  # "{}" truncated
        encode_cursor(0, 1, 2, sha256_of(1)),  # last version beyond until
        encode_cursor(0, 1, 1, "zz"),
        encode_cursor(0, 1, 0, sha256_of(1)),  # last version not after since
        "A" * 600,
    ],
)
def test_invalid_cursor_is_rejected(client: TestClient, engine: Engine, cursor: str) -> None:
    publish(engine, add=[sha256_of(1)])

    response = client.get("/v1/signatures/delta", params={"since": 0, "cursor": cursor})

    assert response.status_code in (400, 422)


def test_cursor_from_reset_database_is_409(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1)])

    cursor = encode_cursor(0, 9, 5, sha256_of(1))
    response = client.get("/v1/signatures/delta", params={"since": 0, "cursor": cursor})

    assert response.status_code == 409


def parse_ndjson(content: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in content.decode().splitlines()]


def test_full_snapshot_streams_ndjson(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(3), sha256_of(1), sha256_of(2)])
    publish(engine, remove=[sha256_of(2)])

    with client.stream(
        "GET", "/v1/signatures/full", headers={"Accept-Encoding": "gzip"}
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/x-ndjson"
        assert response.headers["content-encoding"] == "gzip"
        raw = b"".join(response.iter_raw())
    lines = parse_ndjson(gzip.decompress(raw))

    header, *signatures, end = lines
    assert header["type"] == "header"
    assert (header["format"], header["version"], header["count"]) == (1, 2, 2)
    assert [s["hash"] for s in signatures] == [sha256_of(1), sha256_of(3)]
    assert signatures[0] == {
        "hash": sha256_of(1),
        "algorithm": "sha256",
        "family": "TestFamily",
        "severity": "high",
    }
    assert end == {"type": "end", "version": 2, "count": 2}


def test_full_snapshot_escapes_family(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1)], family='Evil "quoted" \\ family')

    lines = parse_ndjson(client.get("/v1/signatures/full").content)

    assert lines[1]["family"] == 'Evil "quoted" \\ family'


def test_full_snapshot_of_empty_database(client: TestClient) -> None:
    lines = parse_ndjson(client.get("/v1/signatures/full").content)

    assert lines == [
        {"type": "header", "format": 1, "version": 0, "count": 0, "created_at": None},
        {"type": "end", "version": 0, "count": 0},
    ]


def test_full_then_delta(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(i) for i in range(5)])
    lines = parse_ndjson(client.get("/v1/signatures/full").content)
    state: State = {s["hash"]: (s["algorithm"], s["family"], s["severity"]) for s in lines[1:-1]}
    version = lines[0]["version"]
    publish(engine, add=[sha256_of(9)], remove=[sha256_of(0)])

    state, until, _ = sync_delta(client, state, version, limit=100)

    assert until == 2
    assert state == active_state(engine)
