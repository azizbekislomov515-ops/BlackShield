#!/usr/bin/env python3
"""Example BlackShield signature sync client (Python standard library only).

Mirrors what the Android app does: keeps a local SQLite signature store in sync with the
backend, using a full snapshot for the first sync and deltas afterwards, then looks hashes up.

    export BLACKSHIELD_API_KEY=bs_...           # never pass keys on the command line
    python examples/sync_client.py --base-url http://localhost:8000 --db signatures.db sync
    python examples/sync_client.py --base-url http://localhost:8000 lookup <sha256> [...]

See docs/sync-protocol.md for the protocol this implements.
"""

import argparse
import gzip
import io
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

USER_AGENT = "blackshield-example-client/1.0"
INSERT_BATCH = 10_000


class SyncError(Exception):
    pass


class Api:
    def __init__(self, base_url: str, api_key: str, timeout: float = 60.0) -> None:
        if not base_url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise SyncError("refusing to send the API key over plain HTTP to a remote host")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    @contextmanager
    def request(
        self, method: str, path: str, params: dict[str, Any] | None = None, body: Any = None
    ) -> Iterator[Any]:
        """Yield a binary, gzip-decoded response stream. Retries 429 / 5xx with backoff."""
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        headers = {
            "X-API-Key": self.api_key,
            "Accept-Encoding": "gzip",
            "User-Agent": USER_AGENT,
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(5):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310
            try:
                response = urllib.request.urlopen(req, timeout=self.timeout)  # noqa: S310
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 500, 502, 503, 504) and attempt < 4:
                    delay = float(exc.headers.get("Retry-After") or 2**attempt)
                    time.sleep(min(delay, 60.0))
                    continue
                raise
            with response:
                if response.headers.get("Content-Encoding") == "gzip":
                    yield io.BufferedReader(gzip.GzipFile(fileobj=response))  # streaming
                else:
                    yield response
            return

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        with self.request("GET", path, params) as stream:
            return json.load(stream)

    def post_json(self, path: str, body: Any) -> Any:
        with self.request("POST", path, body=body) as stream:
            return json.load(stream)


def open_store(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, isolation_level=None)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS signatures (
            hash TEXT PRIMARY KEY, algorithm TEXT NOT NULL, family TEXT, severity TEXT NOT NULL
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """
    )
    return db


def local_version(db: sqlite3.Connection) -> int:
    row = db.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
    return int(row[0]) if row else 0


def set_version(db: sqlite3.Connection, version: int) -> None:
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('version', ?)", (str(version),))


def full_sync(api: Api, db: sqlite3.Connection) -> dict[str, Any]:
    """Replace the local store with the snapshot, atomically. A truncated stream is discarded."""
    db.execute("BEGIN")
    try:
        db.execute("DELETE FROM signatures")
        with api.request("GET", "/v1/signatures/full") as stream:
            header = json.loads(stream.readline())
            if header.get("type") != "header" or header.get("format") != 1:
                raise SyncError("unsupported snapshot format")
            batch: list[tuple[str, str, str | None, str]] = []
            received = 0
            end: dict[str, Any] | None = None
            for raw in stream:
                item = json.loads(raw)
                if item.get("type") == "end":
                    end = item
                    break
                batch.append((item["hash"], item["algorithm"], item["family"], item["severity"]))
                received += 1
                if len(batch) >= INSERT_BATCH:
                    db.executemany("INSERT INTO signatures VALUES (?, ?, ?, ?)", batch)
                    batch.clear()
            db.executemany("INSERT INTO signatures VALUES (?, ?, ?, ?)", batch)
        if end is None or end["count"] != received or end["version"] != header["version"]:
            raise SyncError("snapshot stream was truncated")
        set_version(db, header["version"])
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    return {"mode": "full", "version": header["version"], "signatures": received}


def delta_sync(api: Api, db: sqlite3.Connection, since: int) -> dict[str, Any]:
    """Apply every page in one local transaction, then store `until` as the new version."""
    added = removed = 0
    cursor: str | None = None
    db.execute("BEGIN")
    try:
        while True:
            params: dict[str, Any] = {"since": since}
            if cursor:
                params["cursor"] = cursor
            page = api.get_json("/v1/signatures/delta", params)
            db.executemany(
                "INSERT OR REPLACE INTO signatures VALUES (?, ?, ?, ?)",
                [
                    (a["hash"], a["algorithm"], a["family"], a["severity"])
                    for a in page["additions"]
                ],
            )
            db.executemany(
                "DELETE FROM signatures WHERE hash = ?", [(r["hash"],) for r in page["removals"]]
            )
            added += len(page["additions"])
            removed += len(page["removals"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        set_version(db, page["until"])
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    return {"mode": "delta", "version": page["until"], "added": added, "removed": removed}


def sync(api: Api, db: sqlite3.Connection) -> dict[str, Any]:
    remote = api.get_json("/v1/signatures/version")["version"]
    local = local_version(db)
    if local == remote:
        return {"mode": "none", "version": local}
    if local == 0:
        return full_sync(api, db)
    try:
        return delta_sync(api, db, local)
    except urllib.error.HTTPError as exc:
        if exc.code == 409:  # local version is ahead of the server (e.g. server was rebuilt)
            return full_sync(api, db)
        raise


def lookup(api: Api, hashes: list[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for start in range(0, len(hashes), 100):  # the API accepts at most 100 per request
        body = api.post_json("/v1/reputation/lookup", {"hashes": hashes[start : start + 100]})
        results += body["results"]
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--db", default="signatures.db", help="local SQLite store")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("sync", help="bring the local store up to date")
    look = sub.add_parser("lookup", help="look up SHA-256 hashes")
    look.add_argument("hashes", nargs="+")
    args = parser.parse_args(argv)

    api_key = os.environ.get("BLACKSHIELD_API_KEY")
    if not api_key:
        print("set BLACKSHIELD_API_KEY", file=sys.stderr)
        return 1
    api = Api(args.base_url, api_key)
    try:
        if args.command == "sync":
            db = open_store(args.db)
            try:
                result = sync(api, db)
                result["local_count"] = db.execute("SELECT count(*) FROM signatures").fetchone()[0]
            finally:
                db.close()
            print(json.dumps(result))
        else:
            for item in lookup(api, args.hashes):
                print(json.dumps(item))
    except (urllib.error.URLError, SyncError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
