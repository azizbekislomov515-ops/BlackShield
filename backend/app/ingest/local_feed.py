"""Importer for local CSV / JSON / NDJSON signature feeds.

Every format carries the same fields per record:

    hash        required; hex digest, any case
    algorithm   optional; md5 | sha1 | sha256 (inferred from the length when absent)
    family      optional; malware family name
    severity    optional; low | medium | high | critical (default from the caller)
    first_seen  optional; ISO 8601 timestamp, UTC when no offset is given
    action      optional; "add" (default) or "remove"

CSV needs a header row. JSON is an array of objects (loaded at once, so prefer CSV or NDJSON
for large feeds). NDJSON (.ndjson / .jsonl) has one object per line. CSV and NDJSON are
streamed, so feeds of any size import in constant memory.
"""

import csv
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.signatures.normalize import (
    InvalidRecord,
    Removal,
    SignatureRecord,
    normalize_hash,
    normalize_severity,
    normalize_source,
    record_from_mapping,
)
from app.signatures.store import ApplyResult, apply_changes

logger = logging.getLogger(__name__)

FeedFormat = Literal["csv", "json", "ndjson"]
_EXTENSIONS: dict[str, FeedFormat] = {
    ".csv": "csv",
    ".json": "json",
    ".ndjson": "ndjson",
    ".jsonl": "ndjson",
}
_MAX_REPORTED_ERRORS = 20


@dataclass
class FeedReport:
    records: int = 0
    rejected: int = 0
    errors: list[str] = field(default_factory=list)
    result: ApplyResult = field(default_factory=ApplyResult)

    def reject(self, location: str, reason: str) -> None:
        self.rejected += 1
        if len(self.errors) < _MAX_REPORTED_ERRORS:
            self.errors.append(f"{location}: {reason}")


def detect_format(path: Path) -> FeedFormat:
    try:
        return _EXTENSIONS[path.suffix.lower()]
    except KeyError:
        raise ValueError(f"unknown feed format for {path.name!r}; pass --format") from None


def default_source(path: Path) -> str:
    stem = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in path.stem.lower())
    return normalize_source(f"local:{stem}"[:64])


def iter_raw_records(path: Path, fmt: FeedFormat) -> Iterator[tuple[str, Any]]:
    """Yield ``(location, raw_record)`` pairs; location is used in error messages."""
    if fmt == "csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or "hash" not in [
                f.strip().lower() for f in reader.fieldnames
            ]:
                raise ValueError("CSV feed needs a header row with a 'hash' column")
            for row in reader:
                cleaned = {
                    (k or "").strip().lower(): (v.strip() if isinstance(v, str) else v)
                    for k, v in row.items()
                }
                yield f"line {reader.line_num}", {k: v or None for k, v in cleaned.items()}
    elif fmt == "ndjson":
        with path.open(encoding="utf-8-sig") as handle:
            for number, line in enumerate(handle, start=1):
                if line.strip():
                    try:
                        yield f"line {number}", json.loads(line)
                    except json.JSONDecodeError:
                        yield f"line {number}", None
    else:
        with path.open(encoding="utf-8-sig") as handle:
            data = json.load(handle)
        if not isinstance(data, list):
            raise ValueError("JSON feed must be an array of objects")
        for index, item in enumerate(data):
            yield f"item {index}", item


def parse_feed(
    path: Path,
    *,
    source: str,
    default_severity: str,
    fmt: FeedFormat | None = None,
    now: datetime | None = None,
    report: FeedReport | None = None,
) -> Iterator[SignatureRecord | Removal]:
    """Lazily turn a feed file into normalized changes, recording rejects in ``report``."""
    now = now or datetime.now(UTC)
    report = report if report is not None else FeedReport()
    source = normalize_source(source)
    default_severity = normalize_severity(default_severity, "high")
    for location, raw in iter_raw_records(path, fmt or detect_format(path)):
        report.records += 1
        if not isinstance(raw, dict):
            report.reject(location, "not a JSON object")
            continue
        raw = {str(k).lower(): v for k, v in raw.items()}
        action = str(raw.get("action") or "add").strip().lower()
        try:
            if action == "add":
                yield record_from_mapping(
                    raw, source=source, default_severity=default_severity, now=now
                )
            elif action == "remove":
                digest, _ = normalize_hash(raw.get("hash"), raw.get("algorithm"))
                yield Removal(hash=digest)
            else:
                raise InvalidRecord("action must be 'add' or 'remove'")
        except InvalidRecord as exc:
            report.reject(location, str(exc))


def import_feed(
    session: Session,
    path: Path,
    *,
    source: str | None = None,
    default_severity: str = "high",
    fmt: FeedFormat | None = None,
    now: datetime | None = None,
) -> FeedReport:
    report = FeedReport()
    changes = parse_feed(
        path,
        source=source or default_source(path),
        default_severity=default_severity,
        fmt=fmt,
        now=now,
        report=report,
    )
    report.result = apply_changes(session, changes, now=now)
    logger.info(
        "feed import finished",
        extra={
            "feed": path.name,
            "records": report.records,
            "rejected": report.rejected,
            "version": report.result.version,
            "added": report.result.added + report.result.resurrected,
            "removed": report.result.removed,
        },
    )
    return report
