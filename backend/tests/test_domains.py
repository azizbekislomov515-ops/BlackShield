"""Web Shield domains: normalization, feeds, versioned store, delta API and CLI."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.api.v1.domains import encode_cursor
from app.cli import main
from app.domains.feeds import FeedClient, FeedError, import_domains, ingest_urlhaus, parse_feed
from app.domains.normalize import (
    DomainRecord,
    DomainRemoval,
    InvalidDomain,
    ProtectedDomain,
    blockable,
    normalize_domain,
)
from app.domains.store import apply_domain_changes, replace_source

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def add(
    engine: Engine, *domains: str, source: str = "test", category: str = "malware"
) -> int | None:
    with Session(engine) as db:
        return apply_domain_changes(
            db, [DomainRecord(d, category, source, T0) for d in domains], now=T0
        ).version


def remove(engine: Engine, *domains: str) -> int | None:
    with Session(engine) as db:
        return apply_domain_changes(db, [DomainRemoval(d) for d in domains], now=T0).version


def sync(client: TestClient, since: int, limit: int = 1000) -> tuple[dict[str, str], set[str], int]:
    """Follow every page from ``since``. Returns (additions, removals, until)."""
    additions: dict[str, str] = {}
    removals: set[str] = set()
    cursor: str | None = None
    while True:
        params: dict[str, Any] = {"since": since, "limit": limit}
        if cursor:
            params["cursor"] = cursor
        response = client.get("/v1/domains/delta", params=params)
        assert response.status_code == 200, response.text
        body = response.json()
        for item in body["additions"]:
            assert item["domain"] not in additions and item["domain"] not in removals
            additions[item["domain"]] = item["category"]
        for item in body["removals"]:
            assert item["domain"] not in additions and item["domain"] not in removals
            removals.add(item["domain"])
        cursor = body["next_cursor"]
        if cursor is None:
            return additions, removals, body["until"]


# --- normalization -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Evil.Example.", "evil.example"),
        ("http://evil.example:8080/login?x=1", "evil.example"),
        ("https://user@Login.Evil.example/path", "login.evil.example"),
        ("evil.example/path/page.html", "evil.example"),
        ("evil.example:443", "evil.example"),
        ("*.evil.example", "evil.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("mal_ware.example", "mal_ware.example"),
    ],
)
def test_normalize_domain(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "localhost",
        "192.168.1.1",
        "http://10.0.0.1/x",
        "[::1]",
        "-bad.example",
        "a..example",
        "x" * 64 + ".example",
        "evil.123",
        "exa mple.com",
    ],
)
def test_normalize_rejects(raw: str) -> None:
    with pytest.raises(InvalidDomain):
        normalize_domain(raw)


def test_never_block_list() -> None:
    for raw in [
        "https://docs.google.com/forms/d/e/x",
        "google.com",
        "mail.google.com",
        "bit.ly/abc",
        "github.io",
        "web.app",
    ]:
        with pytest.raises(ProtectedDomain):
            blockable(raw)
    # Customers of shared hosting are blockable; lookalikes of protected names too.
    assert blockable("evil-login.github.io") == "evil-login.github.io"
    assert blockable("paypal.com.account-verify.example") == "paypal.com.account-verify.example"
    assert blockable("google.com-secure.example") == "google.com-secure.example"


# --- feeds ---------------------------------------------------------------------------------------


def test_parse_hosts_list_csv_and_phishtank() -> None:
    hosts = "# URLhaus\n127.0.0.1\tevil.example\n0.0.0.0 a.example b.example # trailing\n\n"
    assert [e for _, e in parse_feed(hosts, "hosts")] == ["evil.example", "a.example", "b.example"]
    assert [e for _, e in parse_feed("! c\nhttp://x.example/a\ny.example\n", "list")] == [
        "http://x.example/a",
        "y.example",
    ]
    assert [e for _, e in parse_feed("url,date\nhttp://p.example/,2026\n", "csv")] == [
        "http://p.example/"
    ]
    phishtank = json.dumps(
        [
            {"url": "http://ph.example/login", "verified": "yes", "online": "yes"},
            {"url": "http://old.example/", "verified": "yes", "online": "no"},
            {"no_url": 1},
        ]
    )
    assert [e for _, e in parse_feed(phishtank, "phishtank")] == ["http://ph.example/login"]
    with pytest.raises(FeedError):
        parse_feed("{}", "phishtank").__next__()
    with pytest.raises(FeedError):
        parse_feed("a,b\n1,2\n", "csv").__next__()


def test_import_counts_invalid_and_protected(engine: Engine) -> None:
    text = (
        "evil.example\nhttp://phish.example/x\n10.0.0.1\nhttps://docs.google.com/x\nevil.example\n"
    )
    with Session(engine) as db:
        report = import_domains(
            db, text, fmt="list", source="local:t", category="phishing", replace=False
        )
    assert (report.entries, report.invalid, report.protected) == (5, 1, 1)
    assert report.result.added == 2
    assert any("docs.google.com" in e for e in report.examples)


def test_replace_source_removes_only_its_own_domains(engine: Engine) -> None:
    add(engine, "shared.example", source="other")
    with Session(engine) as db:
        replace_source(
            db,
            "urlhaus",
            [
                DomainRecord(d, "malware", "urlhaus", T0)
                for d in ("a.example", "b.example", "shared.example")
            ],
        )
    with Session(engine) as db:
        result = replace_source(
            db, "urlhaus", [DomainRecord("b.example", "malware", "urlhaus", T0)]
        )
    assert result.removed == 1  # a.example; shared.example belongs to "other"
    assert result.active_count == 2


def test_replace_refuses_an_empty_feed(engine: Engine) -> None:
    add(engine, "a.example", source="urlhaus")
    with Session(engine) as db, pytest.raises(FeedError, match="no valid entries"):
        import_domains(
            db, "# empty\n", fmt="hosts", source="urlhaus", category="malware", replace=True
        )


def test_ingest_urlhaus_downloads_and_replaces(engine: Engine) -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx2.Response(503)
        return httpx2.Response(200, text="127.0.0.1 evil.example\n127.0.0.1 bad.example\n")

    client = FeedClient(
        http=httpx2.Client(transport=httpx2.MockTransport(handler)), sleep=lambda _: None
    )
    with Session(engine) as db:
        report = ingest_urlhaus(db, client, url="https://feed.test/hostfile", auth_key="k")
    assert report.result.added == 2
    assert seen[-1].headers["Auth-Key"] == "k"


def test_feed_client_gives_up_on_client_errors() -> None:
    client = FeedClient(
        http=httpx2.Client(transport=httpx2.MockTransport(lambda _: httpx2.Response(404))),
        sleep=lambda _: None,
    )
    with pytest.raises(FeedError, match="404"):
        client.get_text("https://feed.test/x")


# --- versioned store and delta API ---------------------------------------------------------------


def test_versions_only_for_real_changes(engine: Engine) -> None:
    assert add(engine, "a.example", "b.example") == 1
    assert add(engine, "a.example") is None  # nothing new
    assert remove(engine, "missing.example") is None
    assert remove(engine, "a.example") == 2
    assert add(engine, "a.example") == 3  # resurrected


def test_version_endpoint(client: TestClient, engine: Engine) -> None:
    assert client.get("/v1/domains/version").json() == {
        "version": 0,
        "created_at": None,
        "count": 0,
    }
    add(engine, "a.example", "b.example")
    body = client.get("/v1/domains/version").json()
    assert (body["version"], body["count"]) == (1, 2)


def test_delta_from_zero_and_skipped_versions(client: TestClient, engine: Engine) -> None:
    add(engine, *(f"d{i}.example" for i in range(25)))
    add(engine, "phish.example", category="phishing")
    remove(engine, "d3.example", "d4.example")
    add(engine, "d3.example")

    everything, gone, until = sync(client, 0, limit=7)
    assert until == 4
    assert len(everything) == 25 and gone == {"d4.example"}
    assert everything["phish.example"] == "phishing"

    since_v2, gone_v2, _ = sync(client, 2, limit=1)
    assert set(since_v2) == {"d3.example"} and gone_v2 == {"d4.example"}


def test_delta_errors(client: TestClient, engine: Engine) -> None:
    add(engine, "a.example")
    assert client.get("/v1/domains/delta", params={"since": 5}).status_code == 409
    assert (
        client.get("/v1/domains/delta", params={"since": 0, "cursor": "garbage"}).status_code == 400
    )
    other_since = encode_cursor(1, 1, 1, "a.example")
    assert (
        client.get("/v1/domains/delta", params={"since": 0, "cursor": other_since}).status_code
        == 400
    )


def test_delta_requires_an_api_key(app_factory, engine: Engine) -> None:  # type: ignore[no-untyped-def]
    with TestClient(app_factory()) as anonymous:
        assert anonymous.get("/v1/domains/delta", params={"since": 0}).status_code == 401


# --- CLI -----------------------------------------------------------------------------------------


def last_json(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    return json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_cli_import_remove_and_status(
    engine: Engine, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    feed = tmp_path / "list.txt"
    feed.write_text("evil.example\nhttp://phish.example/a\nnot a domain\n", encoding="utf-8")
    args = ["domains-import", str(feed), "--source", "local:t", "--category", "phishing"]
    assert main(args, engine=engine) == 0
    report = last_json(capsys)
    assert (report["added"], report["invalid"]) == (2, 1)

    assert main(["domains-remove", "EVIL.example."], engine=engine) == 0
    assert last_json(capsys) == {"version": 2, "removed": 1}
    assert main(["domains-remove", "10.0.0.1"], engine=engine) == 1

    assert main(["domains-status"], engine=engine) == 0
    status = last_json(capsys)
    assert (status["version"], status["count"]) == (2, 1)
    assert (
        main(
            [
                "domains-import",
                str(tmp_path / "missing.txt"),
                "--source",
                "x",
                "--category",
                "malware",
            ],
            engine=engine,
        )
        == 1
    )
