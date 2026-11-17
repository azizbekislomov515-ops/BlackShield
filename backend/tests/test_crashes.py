from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.api.v1.crashes import fingerprint, prune_crash_reports
from app.db.models import CrashReport


def report(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "app_version": "1.0.0",
        "version_code": 10000,
        "android_sdk": 37,
        "occurred_at": "2026-11-14T10:00:00Z",
        "exceptions": ["java.lang.IllegalStateException", "java.io.IOException"],
        "frames": [
            "com.blackshield.app.a.b(SourceFile:12)",
            "android.os.Handler.dispatchMessage(Handler.java:99)",
            "java.lang.reflect.Method.invoke(Native Method)",
        ],
    }
    body.update(overrides)
    return body


def test_stores_only_the_report_fields(client: TestClient, engine: Engine) -> None:
    response = client.post("/v1/crashes", json=report())

    assert response.status_code == 202
    assert response.json() == {"accepted": True}
    with Session(engine) as db:
        row = db.scalars(select(CrashReport)).one()
    assert row.app_version == "1.0.0"
    assert row.android_sdk == 37
    assert row.exception == "java.lang.IllegalStateException"
    assert row.stack.splitlines()[0] == "Caused by: java.io.IOException"
    assert row.fingerprint == fingerprint(report()["exceptions"], report()["frames"])


@pytest.mark.parametrize(
    "overrides",
    [
        # Exception messages and free text are refused: they can carry personal data.
        {"exceptions": ["java.lang.IllegalStateException: /sdcard/Download/my-photo.jpg"]},
        {"frames": ["user typed something here"]},
        {"frames": ["com.example.A.b(/data/user/0/com.example/files/secret.txt:1)"]},
        {"device_id": "abc123"},
        {"frames": []},
        {"frames": ["a.b(SourceFile:1)"] * 65},
        {"android_sdk": 7},
        {"app_version": "1.0.0-debug"},
    ],
)
def test_refuses_anything_beyond_the_promised_shape(
    client: TestClient, overrides: dict[str, Any]
) -> None:
    assert client.post("/v1/crashes", json=report(**overrides)).status_code == 422


def test_needs_an_api_key(app_factory: Any) -> None:
    with TestClient(app_factory()) as anonymous:
        assert anonymous.post("/v1/crashes", json=report()).status_code == 401


def test_future_device_clock_is_clamped(client: TestClient, engine: Engine) -> None:
    client.post("/v1/crashes", json=report(occurred_at="2099-01-01T00:00:00Z"))

    with Session(engine) as db:
        row = db.scalars(select(CrashReport)).one()
    assert row.occurred_at <= row.received_at


def test_prune_deletes_reports_older_than_90_days(client: TestClient, engine: Engine) -> None:
    client.post("/v1/crashes", json=report())
    with Session(engine) as db:
        assert prune_crash_reports(db, now=datetime.now(UTC) + timedelta(days=89)) == 0
        assert prune_crash_reports(db, now=datetime.now(UTC) + timedelta(days=91)) == 1
        assert db.scalars(select(CrashReport)).all() == []
