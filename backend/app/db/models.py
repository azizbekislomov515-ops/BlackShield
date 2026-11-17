"""ORM models. Import every model here so Alembic autogenerate sees it in Base.metadata."""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Identity,
    Index,
    Integer,
    String,
    Text,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime

ALGORITHMS = ("md5", "sha1", "sha256")
SEVERITIES = ("low", "medium", "high", "critical")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Signature(Base):
    """A known-malicious file digest.

    ``version`` is the signature version in which this row last changed: the version that added
    it, or the version that removed it. Removed rows stay as tombstones (``removed = true``) so a
    delta can tell clients to delete them. Because each row carries only its latest change, a
    delta ``WHERE version > since`` is the net change from any older version, however many
    versions were skipped. See docs/sync-protocol.md.
    """

    __tablename__ = "signatures"

    # Lower-case hex digest; the primary key index serves lookups and the snapshot's ORDER BY.
    hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    algorithm: Mapped[str] = mapped_column(String(8))
    family: Mapped[str | None] = mapped_column(String(128))
    source: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    version: Mapped[int] = mapped_column(BigInteger)
    removed: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())

    __table_args__ = (
        CheckConstraint(_in("algorithm", ALGORITHMS), name="algorithm"),
        CheckConstraint(_in("severity", SEVERITIES), name="severity"),
        # Delta pages are keyset scans over (version, hash).
        Index("ix_signatures_version_hash", "version", "hash"),
    )


class SignatureVersion(Base):
    """One row per published signature version. ``count`` is the number of active signatures."""

    __tablename__ = "signature_versions"

    version: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    count: Mapped[int] = mapped_column(BigInteger)


class YaraRuleset(Base):
    """One published, signed YARA ruleset. Rows are never changed; a new version replaces the old.

        ``signature`` is ECDSA P-256 over ``blackshield-yara-rules
    <version>
    <sha256>`` (see
        app/rules/signing.py), made at publish time with a key the API server never holds.
    """

    __tablename__ = "yara_rulesets"

    version: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    sha256: Mapped[str] = mapped_column(String(64))
    key_id: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(Text)
    rules: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())

    __table_args__ = (CheckConstraint("version > 0", name="version_positive"),)


DOMAIN_CATEGORIES = ("malware", "phishing")


class BlockedDomain(Base):
    """A malware or phishing domain for Web Shield. Same versioning model as ``Signature``:
    ``version`` is the version of the row's latest change, and removed rows stay as tombstones so
    a delta can tell clients to delete them (docs/sync-protocol.md, section 8).
    """

    __tablename__ = "blocked_domains"

    # Lower-case ASCII (IDNA) name without a trailing dot; at most 253 characters.
    domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    category: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    version: Mapped[int] = mapped_column(BigInteger)
    removed: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())

    __table_args__ = (
        CheckConstraint(_in("category", DOMAIN_CATEGORIES), name="category"),
        Index("ix_blocked_domains_version_domain", "version", "domain"),
        Index("ix_blocked_domains_source", "source"),
    )


class DomainVersion(Base):
    """One row per published domain-list version. ``count`` is the number of active domains."""

    __tablename__ = "domain_versions"

    version: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    count: Mapped[int] = mapped_column(BigInteger)


__all__ = [
    "ALGORITHMS",
    "DOMAIN_CATEGORIES",
    "SEVERITIES",
    "Base",
    "BlockedDomain",
    "DomainVersion",
    "Signature",
    "SignatureVersion",
    "YaraRuleset",
]


class CrashReport(Base):
    """An app crash, sent only by users who turned crash reports on (off by default).

    Holds no identifier of the device or the person: the app sends its version, the Android SDK
    level, the exception class and the stack frames (class, method, file and line), with exception
    messages removed because they can contain file names or other data. No IP address is stored.
    Rows older than 90 days are deleted (``blackshield-signatures crashes-prune``). See
    docs/privacy.md.
    """

    __tablename__ = "crash_reports"

    # BIGINT IDENTITY in PostgreSQL; SQLite (tests) only auto-increments INTEGER PRIMARY KEY.
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), Identity(), primary_key=True
    )
    received_at: Mapped[datetime] = mapped_column(UTCDateTime())
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime())
    app_version: Mapped[str] = mapped_column(String(32))
    version_code: Mapped[int] = mapped_column(Integer)
    android_sdk: Mapped[int] = mapped_column(Integer)
    exception: Mapped[str] = mapped_column(String(256))
    # SHA-256 of exception + frames: groups reports of the same crash.
    fingerprint: Mapped[str] = mapped_column(String(64))
    stack: Mapped[str] = mapped_column(Text)

    __table_args__ = (
        Index("ix_crash_reports_received_at", "received_at"),
        Index("ix_crash_reports_fingerprint", "fingerprint"),
    )
