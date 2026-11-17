"""API key authentication and rate limiting for /v1.

API keys are random 256-bit tokens. The server only stores ``key_id:sha256(key)`` pairs, so a
leaked configuration does not leak usable keys. Keys have enough entropy that an unsalted hash
is safe, and lookup by hash avoids comparing secrets byte by byte.
"""

import hashlib
import math
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

KEY_PREFIX = "bs_"
_KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
# Presented keys longer than this are rejected before hashing.
MAX_KEY_LENGTH = 256


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


class ApiKeyRing:
    """Verifies presented API keys against configured ``key_id:sha256hex`` entries."""

    def __init__(self, entries: dict[str, str]) -> None:
        self._by_hash = {digest: key_id for key_id, digest in entries.items()}

    @classmethod
    def parse(cls, config: str) -> "ApiKeyRing":
        entries: dict[str, str] = {}
        for raw in config.split(","):
            item = raw.strip()
            if not item:
                continue
            key_id, sep, digest = item.partition(":")
            key_id, digest = key_id.strip(), digest.strip().lower()
            if not sep or not _KEY_ID.fullmatch(key_id) or not _SHA256_HEX.fullmatch(digest):
                # Do not echo the entry: it might be a raw key pasted by mistake.
                raise ValueError("API_KEYS entries must look like key_id:<64 hex sha256>")
            if key_id in entries:
                raise ValueError(f"duplicate API key id {key_id!r}")
            entries[key_id] = digest
        return cls(entries)

    def __len__(self) -> int:
        return len(self._by_hash)

    def verify(self, presented: str | None) -> str | None:
        """Return the key id for a valid key, else None."""
        if not presented or len(presented) > MAX_KEY_LENGTH:
            return None
        # Lookup by SHA-256 of the presented key: lookup timing depends only on the hash,
        # which reveals nothing about any configured key.
        return self._by_hash.get(hash_api_key(presented))


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int  # seconds until one request is allowed again (0 if allowed)


class RateLimiter:
    """In-process token bucket per key. Thread-safe; the number of tracked keys is bounded.

    State is per process: with N API replicas the effective limit is N times higher. Put a
    shared limiter (gateway or Redis) in front when scaling out.
    """

    def __init__(
        self,
        *,
        per_minute: int,
        burst: int,
        max_keys: int = 100_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.capacity = burst
        self.rate = per_minute / 60.0
        self._max_keys = max_keys
        self._clock = clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def hit(self, key: str) -> RateDecision:
        now = self._clock()
        with self._lock:
            tokens, updated = self._buckets.pop(key, (float(self.capacity), now))
            tokens = min(float(self.capacity), tokens + (now - updated) * self.rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self._max_keys:
                self._buckets.popitem(last=False)  # evict least recently used
        retry_after = 0 if allowed else max(1, math.ceil((1.0 - tokens) / self.rate))
        return RateDecision(allowed, self.capacity, int(tokens), retry_after)
