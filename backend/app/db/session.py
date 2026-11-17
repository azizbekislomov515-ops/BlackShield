from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated, Any

from fastapi import Depends
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session

from app.core.config import get_settings


def make_engine(url: str, **kwargs: Any) -> Engine:
    """Create an engine. SQLite (tests only) gets real transactions, including for SELECTs."""
    if not url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True, **kwargs)

    engine = create_engine(url, connect_args={"check_same_thread": False}, **kwargs)

    # pysqlite only opens a transaction before DML, so a sequence of SELECTs would not see one
    # consistent snapshot. Take over transaction control (SQLAlchemy's documented recipe).
    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None

    @event.listens_for(engine, "begin")
    def _on_begin(connection: Any) -> None:
        connection.exec_driver_sql("BEGIN")

    return engine


@lru_cache
def get_engine() -> Engine:
    # Created lazily so importing the app never opens a database connection.
    return make_engine(get_settings().database_url)


def engine_dependency() -> Engine:
    """FastAPI dependency for the engine; tests override it to point at the test database."""
    return get_engine()


def get_db(engine: Annotated[Engine, Depends(engine_dependency)]) -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    with Session(engine, autoflush=False, expire_on_commit=False) as session:
        yield session


def database_is_reachable() -> bool:
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        return False
    return True
