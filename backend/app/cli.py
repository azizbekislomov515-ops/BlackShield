"""`blackshield-signatures`: signature ingestion and operations.

    blackshield-signatures ingest-malwarebazaar          # pull recent Android samples once
    blackshield-signatures schedule [--interval 3600]    # ... forever, every interval
    blackshield-signatures import-feed feed.csv [--source local:partner]
    blackshield-signatures remove HASH [HASH ...]        # retract false positives
    blackshield-signatures status
    blackshield-signatures generate-api-key --id android-v1
    blackshield-signatures openapi [--output ../docs/openapi.json]

Exit codes: 0 success, 1 failure, 2 partial success (some MalwareBazaar queries failed).
"""

import argparse
import json
import logging
import sys
import threading
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.core.security import generate_api_key, hash_api_key
from app.db.session import make_engine
from app.ingest.local_feed import import_feed
from app.ingest.malwarebazaar import (
    MalwareBazaarClient,
    MalwareBazaarError,
    ingest_malwarebazaar,
)
from app.ingest.scheduler import run_periodically, stop_on_signals
from app.signatures.normalize import InvalidRecord, Removal, normalize_hash
from app.signatures.store import apply_changes, latest_version

logger = logging.getLogger("app.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackshield-signatures", description=__doc__.split("\n")[0]
    )
    sub = parser.add_subparsers(dest="command", required=True)

    mb = sub.add_parser("ingest-malwarebazaar", help="pull recent samples from MalwareBazaar once")
    _add_mb_options(mb)

    schedule = sub.add_parser("schedule", help="run ingest-malwarebazaar periodically")
    _add_mb_options(schedule)
    schedule.add_argument("--interval", type=int, help="seconds between runs (default: settings)")
    schedule.add_argument("--max-runs", type=int, help=argparse.SUPPRESS)

    feed = sub.add_parser("import-feed", help="import a local CSV / JSON / NDJSON feed")
    feed.add_argument("path", type=Path)
    feed.add_argument("--source", help="source name (default: local:<file stem>)")
    feed.add_argument("--format", choices=["csv", "json", "ndjson"], dest="fmt")
    feed.add_argument(
        "--default-severity", default="high", choices=["low", "medium", "high", "critical"]
    )

    remove = sub.add_parser("remove", help="remove signatures (published as a new version)")
    remove.add_argument("hashes", nargs="*")
    remove.add_argument("--file", type=Path, help="file with one hash per line")

    sub.add_parser("status", help="print the latest signature version")

    key = sub.add_parser("generate-api-key", help="create an API key and its API_KEYS entry")
    key.add_argument("--id", required=True, dest="key_id")

    openapi = sub.add_parser("openapi", help="print the OpenAPI document")
    openapi.add_argument("--output", type=Path)
    return parser


def _add_mb_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file-type", action="append", dest="file_types", help="repeatable")
    parser.add_argument("--tag", action="append", dest="tags", help="repeatable")
    parser.add_argument("--limit", type=int, help="samples per query (max 1000)")


def main(argv: Sequence[str] | None = None, *, engine: Engine | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)

    if args.command == "generate-api-key":
        return _generate_api_key(args.key_id)
    if args.command == "openapi":
        return _openapi(args.output)

    engine = engine or make_engine(settings.database_url)
    try:
        if args.command == "ingest-malwarebazaar":
            return _run_mb_once(engine, settings, args)
        if args.command == "schedule":
            return _schedule(engine, settings, args)
        if args.command == "import-feed":
            return _import_feed(engine, args)
        if args.command == "remove":
            return _remove(engine, args)
        if args.command == "status":
            return _status(engine)
    except MalwareBazaarError as exc:
        logger.error("malwarebazaar ingest failed", extra={"error": str(exc)})
        return 1
    raise AssertionError(f"unhandled command {args.command}")


def _mb_client(settings: Settings) -> MalwareBazaarClient:
    key = settings.malwarebazaar_api_key
    return MalwareBazaarClient(
        key.get_secret_value() if key else "",
        base_url=settings.malwarebazaar_url,
        timeout=settings.malwarebazaar_timeout_seconds,
        min_interval=settings.malwarebazaar_min_interval_seconds,
        max_retries=settings.malwarebazaar_max_retries,
    )


def _run_mb_once(engine: Engine, settings: Settings, args: argparse.Namespace) -> int:
    client = _mb_client(settings)
    try:
        with Session(engine) as session:
            report = ingest_malwarebazaar(
                session,
                client,
                file_types=args.file_types or settings.malwarebazaar_file_type_list,
                tags=args.tags if args.tags is not None else settings.malwarebazaar_tag_list,
                limit=min(args.limit or settings.malwarebazaar_limit, 1_000),
            )
    finally:
        client.close()
    _print(
        {
            "version": report.result.version,
            "fetched": report.fetched,
            "added": report.result.added + report.result.resurrected,
            "rejected": report.rejected,
            "failed_queries": report.failed_queries,
            "active_count": report.result.active_count,
        }
    )
    return 0 if report.ok else 2


def _schedule(engine: Engine, settings: Settings, args: argparse.Namespace) -> int:
    # Fail fast on configuration errors instead of logging them every interval.
    _mb_client(settings).close()
    stop = threading.Event()
    stop_on_signals(stop)

    def job() -> None:
        if _run_mb_once(engine, settings, args) != 0:
            logger.warning("scheduled ingest finished with errors")

    run_periodically(
        job,
        interval=args.interval or settings.ingest_interval_seconds,
        stop=stop,
        max_runs=args.max_runs,
    )
    return 0


def _import_feed(engine: Engine, args: argparse.Namespace) -> int:
    try:
        with Session(engine) as session:
            report = import_feed(
                session,
                args.path,
                source=args.source,
                default_severity=args.default_severity,
                fmt=args.fmt,
            )
    except (OSError, ValueError) as exc:
        logger.error("feed import failed", extra={"feed": str(args.path), "error": str(exc)})
        return 1
    _print(
        {
            "version": report.result.version,
            "records": report.records,
            "added": report.result.added + report.result.resurrected,
            "removed": report.result.removed,
            "unchanged": report.result.unchanged,
            "rejected": report.rejected,
            "errors": report.errors,
            "active_count": report.result.active_count,
        }
    )
    return 0


def _remove(engine: Engine, args: argparse.Namespace) -> int:
    raw = list(args.hashes)
    if args.file:
        raw += [line.strip() for line in args.file.read_text().splitlines() if line.strip()]
    if not raw:
        logger.error("no hashes given")
        return 1
    try:
        removals = [Removal(hash=normalize_hash(value)[0]) for value in raw]
    except InvalidRecord as exc:
        logger.error("invalid hash", extra={"error": str(exc)})
        return 1
    with Session(engine) as session:
        result = apply_changes(session, removals)
    _print({"version": result.version, "removed": result.removed})
    return 0


def _status(engine: Engine) -> int:
    with Session(engine) as session:
        latest = latest_version(session)
    _print(
        {
            "version": latest.version if latest else 0,
            "created_at": latest.created_at.isoformat() if latest else None,
            "count": latest.count if latest else 0,
        }
    )
    return 0


def _generate_api_key(key_id: str) -> int:
    key = generate_api_key()
    entry = f"{key_id}:{hash_api_key(key)}"
    print(f"API key (give to the client, store securely; shown once):\n  {key}")
    print(f"Server entry (append to API_KEYS, comma-separated):\n  {entry}")
    return 0


def openapi_document() -> str:
    """The OpenAPI document as committed to docs/openapi.json (independent of .env)."""
    from app.main import create_app

    app = create_app(Settings(_env_file=None))  # type: ignore[call-arg]
    return json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"


def _openapi(output: Path | None) -> int:
    document = openapi_document()
    if output:
        output.write_text(document, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(document)
    return 0


def _print(data: dict[str, object]) -> None:
    print(json.dumps(data, default=str))


if __name__ == "__main__":
    raise SystemExit(main())
