"""Publishing and reading YARA rulesets."""

import re
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import YaraRuleset
from app.rules.signing import sha256_hex, sign, verify

#: Modules compiled into the app's YARA engine; rules importing anything else fail to load.
SUPPORTED_MODULES = frozenset({"dex", "math"})
MAX_RULES_BYTES = 1024 * 1024

_IMPORT = re.compile(r'^\s*import\s+"([^"]*)"', re.MULTILINE)
_INCLUDE = re.compile(r"^\s*include\s", re.MULTILINE)
_RULE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+\w+", re.MULTILINE)


class InvalidRuleset(ValueError):
    """The rules would be rejected by every device; refuse to publish them."""


def check_rules(rules: str) -> None:
    """Cheap checks for mistakes the device would reject. The device compiles before switching."""
    size = len(rules.encode("utf-8"))
    if size == 0 or size > MAX_RULES_BYTES:
        raise InvalidRuleset(f"rules must be 1 byte to {MAX_RULES_BYTES} bytes (got {size})")
    if "\x00" in rules:
        raise InvalidRuleset("rules must not contain NUL characters")
    if _INCLUDE.search(rules):
        raise InvalidRuleset(
            "include directives are not supported: publish one self-contained file"
        )
    unsupported = sorted(set(_IMPORT.findall(rules)) - SUPPORTED_MODULES)
    if unsupported:
        raise InvalidRuleset(f"modules not built into the app: {', '.join(unsupported)}")
    if not _RULE.search(rules):
        raise InvalidRuleset("no rule found")


def latest_ruleset(db: Session) -> YaraRuleset | None:
    return db.scalars(select(YaraRuleset).order_by(YaraRuleset.version.desc()).limit(1)).first()


def publish_ruleset(
    db: Session,
    rules: str,
    *,
    key_id: str,
    key: ec.EllipticCurvePrivateKey,
    min_version: int = 1,
) -> YaraRuleset:
    """Signs ``rules`` as the next version (at least ``min_version``) and stores it.

    ``min_version`` lets the first published version start above the version bundled in the app,
    which devices would otherwise ignore as not newer.
    """
    check_rules(rules)
    with db.begin():
        # Concurrent publishes collide on the primary key; the loser fails and can retry.
        current = db.scalar(select(func.max(YaraRuleset.version))) or 0
        version = max(current + 1, min_version)
        digest = sha256_hex(rules)
        signature = sign(key, version, digest)
        # Never publish something that does not verify (wrong key type, broken environment).
        if not verify(key.public_key(), version, digest, signature):
            raise RuntimeError("signature self-check failed")
        row = YaraRuleset(
            version=version,
            sha256=digest,
            key_id=key_id,
            signature=signature,
            rules=rules,
            created_at=datetime.now(UTC),
        )
        db.add(row)
    return row
