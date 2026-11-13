"""`blackshield-signatures`: signature ingestion and operations.

    blackshield-signatures ingest-malwarebazaar          # pull recent Android samples once
    blackshield-signatures schedule [--interval 3600]    # ... forever, every interval
    blackshield-signatures import-feed feed.csv [--source local:partner]
    blackshield-signatures remove HASH [HASH ...]        # retract false positives
    blackshield-signatures status
    blackshield-signatures generate-api-key --id android-v1
    blackshield-signatures openapi [--output ../docs/openapi.json]
    blackshield-signatures rules-keygen --id k1 --output rules-key.pem
    blackshield-signatures rules-publish rules.yar [--key-file rules-key.pem] [--min-version 2]
    blackshield-signatures rules-status

Exit codes: 0 success, 1 failure, 2 partial success (some MalwareBazaar queries failed).
"""

import argparse
import contextlib
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
from app.rules.signing import SigningKeyError, generate_key, load_private_key
from app.rules.store import InvalidRuleset, latest_ruleset, publish_ruleset
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

    keygen = sub.add_parser("rules-keygen", help="create a YARA rules signing key")
    keygen.add_argument("--id", dest="key_id", required=True, help="key id, e.g. k1")
    keygen.add_argument("--output", type=Path, required=True, help="where to write the private key")

    publish = sub.add_parser("rules-publish", help="sign and publish a YARA ruleset")
    publish.add_argument("path", type=Path, help="the .yar file (UTF-8, self-contained)")
    publish.add_argument("--key-file", type=Path, help="defaults to RULES_SIGNING_KEY_FILE")
    publish.add_argument("--key-id", help="defaults to RULES_SIGNING_KEY_ID")
    publish.add_argument(
        "--min-version",
        type=int,
        default=1,
        help="lowest version to publish as (start above the version bundled in the app)",
    )

    sub.add_parser("rules-status", help="print the latest published YARA ruleset version")
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
    if args.command == "rules-keygen":
        return _rules_keygen(args.key_id, args.output)

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
        if args.command == "rules-publish":
            return _rules_publish(engine, settings, args)
        if args.command == "rules-status":
            return _rules_status(engine)
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


def _rules_keygen(key_id: str, output: Path) -> int:
    if output.exists():
        logger.error("refusing to overwrite an existing key", extra={"path": str(output)})
        return 1
    key = generate_key(key_id)
    output.write_text(key.private_pem, encoding="utf-8")
    with contextlib.suppress(OSError):  # not every file system has POSIX permissions
        output.chmod(0o600)
    print(f"Private key written to {output}. Keep it offline; anyone with it can push rules.")
    print("App setting (Gradle property blackshield.yaraRulesPublicKeys, comma-separated):")
    print(f"  {key.public_spec}")
    return 0


def _rules_publish(engine: Engine, settings: Settings, args: argparse.Namespace) -> int:
    key_path = args.key_file or (
        Path(settings.rules_signing_key_file) if settings.rules_signing_key_file else None
    )
    if key_path is None:
        logger.error("no signing key: pass --key-file or set RULES_SIGNING_KEY_FILE")
        return 1
    try:
        key = load_private_key(key_path.read_text(encoding="utf-8"))
        rules = args.path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, SigningKeyError) as exc:
        logger.error("cannot publish rules", extra={"error": str(exc)})
        return 1
    try:
        with Session(engine) as session:
            row = publish_ruleset(
                session,
                rules,
                key_id=args.key_id or settings.rules_signing_key_id,
                key=key,
                min_version=args.min_version,
            )
            published = {"version": row.version, "sha256": row.sha256, "key_id": row.key_id}
    except InvalidRuleset as exc:
        logger.error("rules rejected", extra={"error": str(exc)})
        return 1
    _print(published)
    return 0


def _rules_status(engine: Engine) -> int:
    with Session(engine) as session:
        row = latest_ruleset(session)
        _print(
            {
                "version": row.version if row else 0,
                "sha256": row.sha256 if row else None,
                "key_id": row.key_id if row else None,
                "published_at": row.created_at.isoformat() if row else None,
            }
        )
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
