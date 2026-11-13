"""Domain feeds: parsing, downloading and importing.

Supported formats (one per feed):

- ``hosts``: hosts-file lines (``0.0.0.0 evil.example``); URLhaus publishes its online malware
  hosts this way (https://urlhaus.abuse.ch/downloads/hostfile/, CC0).
- ``list``: one domain or URL per line (OpenPhish-style and most text feeds).
- ``phishtank``: PhishTank's ``online-valid.json`` (an array of objects with ``url``).
- ``csv``: a header row with a ``domain`` or ``url`` column.

Lines starting with ``#`` or ``!`` are comments. Every entry goes through
``app.domains.normalize.blockable``; invalid and protected entries are counted, never imported.
"""

import csv
import io
import json
import logging
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx2
from sqlalchemy.orm import Session

from app.domains.normalize import (
    DomainRecord,
    InvalidDomain,
    ProtectedDomain,
    blockable,
    validate_category,
)
from app.domains.store import DomainApplyResult, apply_domain_changes, replace_source

logger = logging.getLogger(__name__)

FORMATS = ("hosts", "list", "phishtank", "csv")
URLHAUS_HOSTFILE_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
PHISHTANK_URL = "https://data.phishtank.com/data/{key}/online-valid.json"
MAX_FEED_BYTES = 64 * 1024 * 1024
_HOSTS_ADDRESSES = {"0.0.0.0", "127.0.0.1", "::", "::1"}  # noqa: S104 - sinkhole addresses, not binds


class FeedError(Exception):
    """A feed could not be downloaded or parsed."""


@dataclass
class FeedReport:
    entries: int = 0
    invalid: int = 0
    protected: int = 0
    examples: list[str] = field(default_factory=list)
    result: DomainApplyResult = field(default_factory=DomainApplyResult)

    def reject(self, line: int, raw: str, reason: str, *, protected: bool) -> None:
        if protected:
            self.protected += 1
        else:
            self.invalid += 1
        if len(self.examples) < 10:
            self.examples.append(f"line {line}: {raw[:80]!r}: {reason}")


def parse_feed(text: str, fmt: str) -> Iterator[tuple[int, str]]:
    """(line number, raw entry) pairs from a feed body."""
    if fmt == "phishtank":
        yield from _parse_phishtank(text)
    elif fmt == "csv":
        yield from _parse_csv(text)
    elif fmt in ("hosts", "list"):
        for number, line in enumerate(text.splitlines(), start=1):
            entry = line.split("#", 1)[0].strip()
            if not entry or entry.startswith("!"):
                continue
            if fmt == "hosts":
                parts = entry.split()
                if len(parts) >= 2 and parts[0] in _HOSTS_ADDRESSES:
                    for host in parts[1:]:
                        yield number, host
                    continue
            yield number, entry.split()[0]
    else:
        raise FeedError(f"unknown feed format {fmt!r}; expected one of {', '.join(FORMATS)}")


def _parse_phishtank(text: str) -> Iterator[tuple[int, str]]:
    try:
        rows = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FeedError(f"not JSON ({exc})") from exc
    if not isinstance(rows, list):
        raise FeedError("expected a JSON array")
    for number, row in enumerate(rows, start=1):
        if not isinstance(row, dict) or not isinstance(row.get("url"), str):
            continue
        # online-valid.json only lists verified, online phish; skip anything flagged otherwise.
        if row.get("verified", "yes") != "yes" or row.get("online", "yes") != "yes":
            continue
        yield number, row["url"]


def _parse_csv(text: str) -> Iterator[tuple[int, str]]:
    reader = csv.DictReader(io.StringIO(text))
    column = next((c for c in ("domain", "url", "host") if c in (reader.fieldnames or [])), None)
    if column is None:
        raise FeedError("CSV needs a 'domain', 'url' or 'host' column")
    for number, row in enumerate(reader, start=2):
        value = (row.get(column) or "").strip()
        if value and not value.startswith("#"):
            yield number, value


def to_records(
    entries: Iterable[tuple[int, str]],
    *,
    source: str,
    category: str,
    report: FeedReport,
    now: datetime,
) -> list[DomainRecord]:
    category = validate_category(category)
    records: dict[str, DomainRecord] = {}
    for number, raw in entries:
        report.entries += 1
        try:
            domain = blockable(raw)
        except ProtectedDomain as exc:
            report.reject(number, raw, str(exc), protected=True)
            continue
        except InvalidDomain as exc:
            report.reject(number, raw, str(exc), protected=False)
            continue
        records.setdefault(domain, DomainRecord(domain, category, source, now))
    return list(records.values())


def import_domains(
    session: Session,
    text: str,
    *,
    fmt: str,
    source: str,
    category: str,
    replace: bool,
    now: datetime | None = None,
) -> FeedReport:
    """Import one feed body. ``replace``: the feed is the source's complete current list."""
    now = now or datetime.now(UTC)
    report = FeedReport()
    records = to_records(
        parse_feed(text, fmt), source=source, category=category, report=report, now=now
    )
    if replace and not records:
        # An empty "complete list" is far more likely a broken download than a clean internet.
        raise FeedError(f"{source}: no valid entries; refusing to remove the source's domains")
    report.result = (
        replace_source(session, source, records, now=now)
        if replace
        else apply_domain_changes(session, records, now=now)
    )
    return report


class FeedClient:
    """Downloads feeds with retries on transport errors, 429 and 5xx, and a size cap."""

    def __init__(
        self,
        *,
        http: httpx2.Client | None = None,
        timeout: float = 60.0,
        max_retries: int = 3,
        user_agent: str = "blackshield-backend",
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._http = http or httpx2.Client(timeout=timeout, follow_redirects=True)
        self._max_retries = max_retries
        self._user_agent = user_agent
        self._sleep = sleep

    def close(self) -> None:
        self._http.close()

    def get_text(self, url: str, headers: dict[str, str] | None = None) -> str:
        last: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                with self._http.stream(
                    "GET", url, headers={"User-Agent": self._user_agent, **(headers or {})}
                ) as response:
                    if response.status_code == 429 or response.status_code >= 500:
                        raise FeedError(f"HTTP {response.status_code}")
                    if response.status_code != 200:
                        raise FeedError(f"HTTP {response.status_code} (not retried)")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body += chunk
                        if len(body) > MAX_FEED_BYTES:
                            raise FeedError(f"feed larger than {MAX_FEED_BYTES} bytes")
                    return body.decode("utf-8", errors="replace")
            except FeedError as exc:
                if "not retried" in str(exc) or "larger than" in str(exc):
                    raise
                last = exc
            except httpx2.TransportError as exc:
                last = exc
            if attempt < self._max_retries:
                self._sleep(min(2.0 * 2**attempt, 60.0))
        raise FeedError(f"download failed after {self._max_retries + 1} attempts: {last}")


def ingest_urlhaus(
    session: Session,
    client: FeedClient,
    *,
    url: str = URLHAUS_HOSTFILE_URL,
    auth_key: str | None = None,
) -> FeedReport:
    """URLhaus's online malware hosts (CC0); the list replaces the previous URLhaus list."""
    headers = {"Auth-Key": auth_key} if auth_key else None
    text = client.get_text(url, headers)
    return import_domains(
        session, text, fmt="hosts", source="urlhaus", category="malware", replace=True
    )


def ingest_phishtank(session: Session, client: FeedClient, *, app_key: str) -> FeedReport:
    """PhishTank's verified online phish (needs a free application key; see their terms)."""
    if not app_key:
        raise FeedError("PHISHTANK_APP_KEY is not set")
    text = client.get_text(PHISHTANK_URL.format(key=app_key))
    return import_domains(
        session, text, fmt="phishtank", source="phishtank", category="phishing", replace=True
    )
