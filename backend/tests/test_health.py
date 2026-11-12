from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.api.health import get_database_check
from app.main import create_app


@pytest.fixture
def app():
    application = create_app()
    yield application
    application.dependency_overrides.clear()


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_readiness_ok_when_database_reachable(app, client: TestClient) -> None:
    app.dependency_overrides[get_database_check] = lambda: lambda: True

    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_readiness_503_when_database_unreachable(app, client: TestClient) -> None:
    app.dependency_overrides[get_database_check] = lambda: lambda: False

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "database": "unavailable"}
