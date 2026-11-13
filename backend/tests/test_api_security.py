import json
import logging
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.v1.deps import SecurityState
from app.core.config import Settings
from app.core.logging import JsonFormatter
from app.core.security import ApiKeyRing, RateLimiter, hash_api_key
from tests.conftest import API_KEY, OTHER_API_KEY, sha256_of

V1_ENDPOINTS = [
    ("GET", "/v1/signatures/version"),
    ("GET", "/v1/signatures/delta?since=0"),
    ("GET", "/v1/signatures/full"),
    ("POST", "/v1/reputation/lookup"),
]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize(("method", "path"), V1_ENDPOINTS)
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-API-Key": "wrong"},
        {"Authorization": "Bearer wrong"},
        {"Authorization": f"Basic {API_KEY}"},
        {"X-API-Key": "x" * 1000},
    ],
)
def test_v1_requires_a_valid_key(
    app_factory: Callable[..., FastAPI], method: str, path: str, headers: dict[str, str]
) -> None:
    with TestClient(app_factory()) as client:
        response = client.request(method, path, headers=headers, json={"hashes": [sha256_of(1)]})

    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


@pytest.mark.parametrize(
    "headers", [{"X-API-Key": API_KEY}, {"Authorization": f"Bearer {OTHER_API_KEY}"}]
)
def test_valid_keys_in_either_header(
    app_factory: Callable[..., FastAPI], headers: dict[str, str]
) -> None:
    with TestClient(app_factory()) as client:
        assert client.get("/v1/signatures/version", headers=headers).status_code == 200


def test_no_configured_keys_fails_closed(app_factory: Callable[..., FastAPI]) -> None:
    with TestClient(app_factory(api_keys="")) as client:
        response = client.get("/v1/signatures/version", headers={"X-API-Key": API_KEY})

    assert response.status_code == 401


def test_health_needs_no_key(app_factory: Callable[..., FastAPI]) -> None:
    with TestClient(app_factory()) as client:
        assert client.get("/health").status_code == 200


@pytest.mark.parametrize(
    "config",
    [
        API_KEY,  # a raw key pasted instead of key_id:hash
        "id:" + "a" * 63,
        "bad id:" + "a" * 64,
        f"a:{'a' * 64},a:{'b' * 64}",
    ],
)
def test_invalid_key_configuration_is_rejected(config: str) -> None:
    with pytest.raises(ValueError) as excinfo:
        ApiKeyRing.parse(config)
    assert API_KEY not in str(excinfo.value)


def test_key_ring_accepts_whitespace_and_case() -> None:
    ring = ApiKeyRing.parse(f" a : {hash_api_key('k1').upper()} ,, b:{hash_api_key('k2')} ")

    assert (ring.verify("k1"), ring.verify("k2"), ring.verify("k3"), len(ring)) == (
        "a",
        "b",
        None,
        2,
    )


def install_clock(app: FastAPI, clock: FakeClock) -> None:
    settings = app.state.settings
    state: SecurityState = app.state.security
    state.limiter = RateLimiter(
        per_minute=settings.rate_limit_per_minute, burst=settings.rate_limit_burst, clock=clock
    )
    state.auth_failures = RateLimiter(
        per_minute=settings.auth_failure_limit_per_minute,
        burst=settings.auth_failure_limit_per_minute,
        clock=clock,
    )


def test_rate_limit_per_key(app_factory: Callable[..., FastAPI]) -> None:
    app = app_factory(rate_limit_per_minute=60, rate_limit_burst=3)
    clock = FakeClock()
    install_clock(app, clock)
    with TestClient(app) as client:
        statuses = [
            client.get("/v1/signatures/version", headers={"X-API-Key": API_KEY}).status_code
            for _ in range(4)
        ]
        limited = client.get("/v1/signatures/version", headers={"X-API-Key": API_KEY})
        # Another key has its own bucket.
        other = client.get("/v1/signatures/version", headers={"X-API-Key": OTHER_API_KEY})
        clock.now += 1.0  # 60/min refills one token per second
        refilled = client.get("/v1/signatures/version", headers={"X-API-Key": API_KEY})

    assert statuses == [200, 200, 200, 429]
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "1"
    assert limited.headers["ratelimit-limit"] == "3"
    assert other.status_code == 200
    assert refilled.status_code == 200


def test_auth_failures_are_rate_limited(app_factory: Callable[..., FastAPI]) -> None:
    app = app_factory(auth_failure_limit_per_minute=3)
    install_clock(app, FakeClock())
    with TestClient(app) as client:
        statuses = [
            client.get("/v1/signatures/version", headers={"X-API-Key": "guess"}).status_code
            for _ in range(5)
        ]
        # Valid requests are not affected by another client's failures... nor by our own.
        valid = client.get("/v1/signatures/version", headers={"X-API-Key": API_KEY})

    assert statuses == [401, 401, 401, 429, 429]
    assert valid.status_code == 200


def test_rate_limiter_bounds_memory() -> None:
    limiter = RateLimiter(per_minute=60, burst=1, max_keys=3, clock=FakeClock())
    for key in "abcd":
        limiter.hit(key)

    assert len(limiter._buckets) == 3
    assert limiter.hit("a").allowed  # evicted, so it starts with a full bucket again


def test_body_size_limit_by_content_length(client: TestClient) -> None:
    body = json.dumps({"hashes": [sha256_of(i) for i in range(400)]})

    response = client.post(
        "/v1/reputation/lookup", content=body, headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 413


def test_body_size_limit_for_chunked_bodies(client: TestClient) -> None:
    def chunks():
        yield b'{"hashes": ['
        for i in range(400):
            yield f'"{sha256_of(i)}",'.encode()
        yield b'"' + sha256_of(999).encode() + b'"]}'

    response = client.post(
        "/v1/reputation/lookup", content=chunks(), headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 413


def test_cors_disabled_by_default(client: TestClient) -> None:
    response = client.get("/v1/signatures/version", headers={"Origin": "https://evil.example"})
    preflight = client.options(
        "/v1/signatures/version",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )

    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-origin" not in preflight.headers


def test_cors_allows_only_configured_origins(app_factory: Callable[..., FastAPI]) -> None:
    with TestClient(
        app_factory(cors_allowed_origins="https://admin.blackshield.test"),
        headers={"X-API-Key": API_KEY},
    ) as client:
        allowed = client.get(
            "/v1/signatures/version", headers={"Origin": "https://admin.blackshield.test"}
        )
        denied = client.get("/v1/signatures/version", headers={"Origin": "https://evil.example"})

    assert allowed.headers["access-control-allow-origin"] == "https://admin.blackshield.test"
    assert "access-control-allow-credentials" not in allowed.headers
    assert "access-control-allow-origin" not in denied.headers


@pytest.mark.parametrize(
    "origins",
    ["*", "https://ok.example,*", "https://admin.example/", "https://*.example", "null"],
)
def test_cors_wildcards_and_malformed_origins_are_rejected(origins: str) -> None:
    with pytest.raises(ValidationError):
        Settings(cors_allowed_origins=origins)


def test_security_headers_and_request_id(client: TestClient) -> None:
    response = client.get("/v1/signatures/version", headers={"X-Request-ID": "abc12345-req"})
    generated = client.get("/v1/signatures/version", headers={"X-Request-ID": "bad id\n"})

    assert response.headers["x-request-id"] == "abc12345-req"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert len(generated.headers["x-request-id"]) == 32


def test_logs_are_structured_and_free_of_secrets(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    secret_hash = sha256_of(424242)

    client.post("/v1/reputation/lookup", json={"hashes": [secret_hash]})
    client.get(
        "/v1/signatures/delta?since=0", headers={"X-API-Key": "wrong-key-should-not-be-logged"}
    )

    formatter = JsonFormatter()
    lines = [formatter.format(r) for r in caplog.records]
    access = [json.loads(line) for line in lines if '"message": "request"' in line]
    assert {(a["path"], a["status"], a["key_id"]) for a in access} == {
        ("/v1/reputation/lookup", 200, "android"),
        ("/v1/signatures/delta", 401, None),
    }
    text = "\n".join(lines)
    for secret in (API_KEY, "wrong-key-should-not-be-logged", secret_hash, "testclient"):
        assert secret not in text


def test_docs_can_be_disabled(app_factory: Callable[..., FastAPI]) -> None:
    with TestClient(app_factory(docs_enabled=False)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
