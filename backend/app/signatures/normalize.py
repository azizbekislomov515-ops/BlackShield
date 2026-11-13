"""Validation and normalization of signature records from any feed."""

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.db.models import SEVERITIES

ALGORITHM_HEX_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_ALGORITHM_BY_LENGTH = {length: name for name, length in ALGORITHM_HEX_LENGTHS.items()}
_HEX = re.compile(r"[0-9a-f]+")
_SOURCE = re.compile(r"[a-z0-9][a-z0-9:._-]{0,63}")
FAMILY_MAX_LENGTH = 128


class InvalidRecord(ValueError):
    """A feed record that cannot be imported. The message never contains secrets."""


@dataclass(frozen=True, slots=True)
class SignatureRecord:
    """A normalized signature to add (or re-add)."""

    hash: str
    algorithm: str
    family: str | None
    severity: str
    source: str
    first_seen: datetime


@dataclass(frozen=True, slots=True)
class Removal:
    """A normalized request to remove a signature."""

    hash: str


def normalize_algorithm(value: str) -> str:
    name = value.strip().lower().replace("-", "").replace("_", "")
    if name not in ALGORITHM_HEX_LENGTHS:
        raise InvalidRecord(f"unsupported algorithm {value[:16]!r}")
    return name


def normalize_hash(value: Any, algorithm: Any = None) -> tuple[str, str]:
    """Return ``(lower_hex, algorithm)``. The algorithm is inferred from the length if absent."""
    if not isinstance(value, str):
        raise InvalidRecord("hash must be a string")
    if algorithm is not None and not isinstance(algorithm, str):
        raise InvalidRecord("algorithm must be a string")
    digest = value.strip().lower()
    if not digest or not _HEX.fullmatch(digest):
        raise InvalidRecord("hash is not hexadecimal")
    if algorithm is None or not algorithm.strip():
        inferred = _ALGORITHM_BY_LENGTH.get(len(digest))
        if inferred is None:
            raise InvalidRecord(f"hash has {len(digest)} hex digits; expected 32, 40 or 64")
        return digest, inferred
    name = normalize_algorithm(algorithm)
    if len(digest) != ALGORITHM_HEX_LENGTHS[name]:
        raise InvalidRecord(
            f"{name} hash must have {ALGORITHM_HEX_LENGTHS[name]} hex digits, got {len(digest)}"
        )
    return digest, name


def normalize_family(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidRecord("family must be a string")
    # Drop control and format characters, collapse whitespace.
    cleaned = "".join(ch for ch in value if unicodedata.category(ch)[0] != "C" or ch == " ")
    cleaned = " ".join(cleaned.split())
    return cleaned[:FAMILY_MAX_LENGTH] or None


def normalize_severity(value: Any, default: str) -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    if not isinstance(value, str) or value.strip().lower() not in SEVERITIES:
        raise InvalidRecord(f"severity must be one of {', '.join(SEVERITIES)}")
    return value.strip().lower()


def normalize_source(value: str) -> str:
    source = value.strip().lower()
    if not _SOURCE.fullmatch(source):
        raise InvalidRecord("source must match [a-z0-9][a-z0-9:._-]{0,63}")
    return source


def parse_timestamp(value: Any, default: datetime) -> datetime:
    """Parse ISO 8601 or MalwareBazaar's ``YYYY-MM-DD HH:MM:SS``. Naive values are UTC."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    if not isinstance(value, str):
        raise InvalidRecord("first_seen must be a string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise InvalidRecord("first_seen is not an ISO 8601 timestamp") from exc
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def record_from_mapping(
    raw: Mapping[str, Any], *, source: str, default_severity: str, now: datetime
) -> SignatureRecord:
    """Build a record from a feed row with keys hash, algorithm, family, severity, first_seen."""
    digest, algorithm = normalize_hash(raw.get("hash"), raw.get("algorithm"))
    return SignatureRecord(
        hash=digest,
        algorithm=algorithm,
        family=normalize_family(raw.get("family")),
        severity=normalize_severity(raw.get("severity"), default_severity),
        source=source,
        first_seen=parse_timestamp(raw.get("first_seen"), now),
    )
