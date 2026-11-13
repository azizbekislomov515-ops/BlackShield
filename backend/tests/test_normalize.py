from datetime import UTC, datetime

import pytest

from app.signatures.normalize import (
    InvalidRecord,
    normalize_family,
    normalize_hash,
    normalize_severity,
    normalize_source,
    parse_timestamp,
    record_from_mapping,
)

NOW = datetime(2026, 11, 13, tzinfo=UTC)


@pytest.mark.parametrize(
    ("value", "expected_algorithm"),
    [("A" * 32, "md5"), ("b" * 40, "sha1"), ("  " + "C" * 64 + "\n", "sha256")],
)
def test_hash_is_lowercased_and_algorithm_inferred(value: str, expected_algorithm: str) -> None:
    digest, algorithm = normalize_hash(value)

    assert digest == value.strip().lower()
    assert algorithm == expected_algorithm


@pytest.mark.parametrize("algorithm", ["SHA-256", "sha256", "Sha_256"])
def test_algorithm_names_are_normalized(algorithm: str) -> None:
    assert normalize_hash("a" * 64, algorithm) == ("a" * 64, "sha256")


@pytest.mark.parametrize(
    ("value", "algorithm"),
    [
        ("a" * 63, None),  # odd length
        ("a" * 48, None),  # no algorithm has 48 digits
        ("g" * 64, None),  # not hex
        ("0x" + "a" * 62, None),
        ("", None),
        ("a" * 32, "sha256"),  # length does not match the declared algorithm
        ("a" * 64, "sha512"),  # unsupported algorithm
        (123, None),
        ("a" * 64, 256),
    ],
)
def test_invalid_hashes_are_rejected(value: object, algorithm: object) -> None:
    with pytest.raises(InvalidRecord):
        normalize_hash(value, algorithm)


def test_family_is_cleaned_and_truncated() -> None:
    assert normalize_family("  Hydra\x00\n  banker​ ") == "Hydra banker"
    assert normalize_family("x" * 300) == "x" * 128
    assert normalize_family("   ") is None
    assert normalize_family(None) is None


def test_severity_defaults_and_validates() -> None:
    assert normalize_severity(None, "high") == "high"
    assert normalize_severity(" CRITICAL ", "high") == "critical"
    with pytest.raises(InvalidRecord):
        normalize_severity("severe", "high")


def test_source_is_validated() -> None:
    assert normalize_source("Local:Partner-1") == "local:partner-1"
    with pytest.raises(InvalidRecord):
        normalize_source("bad source; drop table")


def test_timestamps_accept_iso_and_malwarebazaar_formats() -> None:
    assert parse_timestamp("2026-03-01 05:57:01", NOW) == datetime(2026, 3, 1, 5, 57, 1, tzinfo=UTC)
    assert parse_timestamp("2026-03-01T07:57:01+02:00", NOW) == datetime(
        2026, 3, 1, 5, 57, 1, tzinfo=UTC
    )
    assert parse_timestamp("2026-03-01T05:57:01Z", NOW).tzinfo is UTC
    assert parse_timestamp(None, NOW) == NOW
    with pytest.raises(InvalidRecord):
        parse_timestamp("yesterday", NOW)


def test_record_from_mapping() -> None:
    rec = record_from_mapping(
        {"hash": "AB" * 32, "family": "Joker", "severity": "medium"},
        source="local:test",
        default_severity="high",
        now=NOW,
    )

    assert rec.hash == "ab" * 32
    assert rec.algorithm == "sha256"
    assert (rec.family, rec.severity, rec.source, rec.first_seen) == (
        "Joker",
        "medium",
        "local:test",
        NOW,
    )
