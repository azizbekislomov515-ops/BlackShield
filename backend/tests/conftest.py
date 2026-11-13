"""Shared fixtures.

Tests run against a migrated test database: a temporary SQLite file by default, or PostgreSQL
when ``TEST_DATABASE_URL`` is set (CI does both). The schema is created by running the Alembic
migrations, and every test starts with empty tables.
"""

import os
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, delete, make_url
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import hash_api_key
from app.db.models import Signature, SignatureVersion, YaraRuleset
from app.db.session import engine_dependency, make_engine
from app.main import create_app
from app.signatures.normalize import Removal, SignatureRecord
from app.signatures.store import ApplyResult, apply_changes

BACKEND_DIR = Path(__file__).resolve().parent.parent
API_KEY = "bs_test-key-0123456789abcdefghijklmnopqrstuv"
OTHER_API_KEY = "bs_other-key-0123456789abcdefghijklmnopqrstu"
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def alembic_config(url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    config.attributes["configure_logger"] = False
    return config


@pytest.fixture(scope="session")
def database_url(tmp_path_factory: pytest.TempPathFactory) -> str:
    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        # Migrations are downgraded to base first: refuse anything that is not a test database.
        if "test" not in (make_url(url).database or ""):
            raise RuntimeError("TEST_DATABASE_URL must name a database containing 'test'")
        return url
    return f"sqlite:///{tmp_path_factory.mktemp('db') / 'test.sqlite3'}"


@pytest.fixture(scope="session")
def migrated_engine(database_url: str) -> Iterator[Engine]:
    config = alembic_config(database_url)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    engine = make_engine(database_url)
    yield engine
    engine.dispose()


@pytest.fixture
def engine(migrated_engine: Engine) -> Engine:
    with Session(migrated_engine) as session, session.begin():
        session.execute(delete(Signature))
        session.execute(delete(SignatureVersion))
        session.execute(delete(YaraRuleset))
    return migrated_engine


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    with Session(engine) as db:
        yield db


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "api_keys": f"android:{hash_api_key(API_KEY)},other:{hash_api_key(OTHER_API_KEY)}",
        "rate_limit_per_minute": 6_000,
        "rate_limit_burst": 1_000,
        "log_json": True,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[call-arg]


@pytest.fixture
def app_factory(engine: Engine) -> Callable[..., FastAPI]:
    def factory(**overrides: object) -> FastAPI:
        app = create_app(make_settings(**overrides))
        app.dependency_overrides[engine_dependency] = lambda: engine
        return app

    return factory


@pytest.fixture
def client(app_factory: Callable[..., FastAPI]) -> Iterator[TestClient]:
    with TestClient(app_factory(), headers={"X-API-Key": API_KEY}) as test_client:
        yield test_client


def sha256_of(n: int) -> str:
    return f"{n:064x}"


def record(
    digest: str,
    *,
    algorithm: str = "sha256",
    family: str | None = "TestFamily",
    severity: str = "high",
    source: str = "test",
    first_seen: datetime = T0,
) -> SignatureRecord:
    return SignatureRecord(
        hash=digest,
        algorithm=algorithm,
        family=family,
        severity=severity,
        source=source,
        first_seen=first_seen,
    )


def publish(
    engine: Engine,
    add: list[str] | None = None,
    remove: list[str] | None = None,
    *,
    family: str | None = "TestFamily",
    at: datetime | None = None,
) -> ApplyResult:
    changes: list[SignatureRecord | Removal] = [record(h, family=family) for h in add or []]
    changes += [Removal(hash=h) for h in remove or []]
    with Session(engine) as db:
        return apply_changes(db, changes, now=at or T0 + timedelta(hours=1))
