import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from tests.conftest import publish, sha256_of


def test_lookup_returns_verdicts_in_request_order(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1), sha256_of(2)])
    publish(engine, remove=[sha256_of(2)])

    response = client.post(
        "/v1/reputation/lookup",
        json={"hashes": [sha256_of(3), sha256_of(1).upper(), sha256_of(2), sha256_of(3)]},
    )

    assert response.status_code == 200
    assert response.json() == {
        "version": 2,
        "results": [
            {"hash": sha256_of(3), "verdict": "unknown", "family": None, "severity": None},
            {
                "hash": sha256_of(1),
                "verdict": "malicious",
                "family": "TestFamily",
                "severity": "high",
            },
            {"hash": sha256_of(2), "verdict": "unknown", "family": None, "severity": None},
        ],
    }


def test_lookup_accepts_100_hashes(client: TestClient) -> None:
    response = client.post(
        "/v1/reputation/lookup", json={"hashes": [sha256_of(i) for i in range(100)]}
    )

    assert response.status_code == 200
    assert len(response.json()["results"]) == 100


@pytest.mark.parametrize(
    "body",
    [
        {"hashes": [sha256_of(i) for i in range(101)]},
        {"hashes": []},
        {"hashes": ["a" * 32]},  # MD5: SHA-256 only
        {"hashes": ["z" * 64]},
        {"hashes": [12]},
        {"hashes": "a" * 64},
        {"hashes": [sha256_of(1)], "file": "TVqQAAMAAAAEAAAA"},  # no extra fields, no contents
        {},
    ],
)
def test_lookup_rejects_invalid_bodies(client: TestClient, body: object) -> None:
    assert client.post("/v1/reputation/lookup", json=body).status_code == 422


def test_lookup_rejects_non_json(client: TestClient) -> None:
    response = client.post(
        "/v1/reputation/lookup", content=b"hashes=abc", headers={"Content-Type": "text/plain"}
    )

    assert response.status_code == 422
