from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine

from tests.conftest import API_KEY, publish, sha256_of


def scrape(client: TestClient, **headers: str) -> str:
    response = client.get("/metrics", headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    return response.text


def test_counts_requests_by_route_template_not_raw_path(client: TestClient) -> None:
    client.get("/v1/signatures/version")
    client.get("/no/such/path/a1b2c3")

    text = scrape(client)

    assert 'route="/v1/signatures/version"' in text
    assert 'route="unmatched"' in text
    assert "a1b2c3" not in text  # raw paths never become labels


def test_reports_published_versions(client: TestClient, engine: Engine) -> None:
    publish(engine, add=[sha256_of(1), sha256_of(2)])

    text = scrape(client)

    assert 'blackshield_published_version{dataset="signatures"} 1.0' in text
    assert "blackshield_active_signatures 2.0" in text


def test_counts_auth_failures_and_never_labels_clients(app_factory: Any) -> None:
    with TestClient(app_factory()) as anonymous:
        anonymous.get("/v1/signatures/version", headers={"X-API-Key": "bs_wrong"})
        text = scrape(anonymous)

    assert "blackshield_auth_failures_total" in text
    assert "bs_wrong" not in text
    assert API_KEY not in text
    assert "testclient" not in text  # the client host


def test_token_protects_metrics(app_factory: Any) -> None:
    with TestClient(app_factory(metrics_token="s3cret-scrape-token")) as client:
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
        scrape(client, Authorization="Bearer s3cret-scrape-token")


def test_can_be_disabled(app_factory: Any) -> None:
    with TestClient(app_factory(metrics_enabled=False)) as client:
        assert client.get("/metrics").status_code == 404
