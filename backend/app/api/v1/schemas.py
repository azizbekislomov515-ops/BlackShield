from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Algorithm = Literal["md5", "sha1", "sha256"]
Severity = Literal["low", "medium", "high", "critical"]
Sha256Hex = Annotated[
    str,
    StringConstraints(strip_whitespace=True, to_lower=True, pattern=r"^[0-9a-fA-F]{64}$"),
]
MAX_LOOKUP_HASHES = 100


class VersionResponse(BaseModel):
    version: int = Field(description="Latest published signature version; 0 if none.")
    created_at: datetime | None = Field(description="When that version was published.")
    count: int = Field(description="Active signatures in that version.")


class DeltaAddition(BaseModel):
    hash: str
    algorithm: Algorithm
    family: str | None
    severity: Severity
    version: int


class DeltaRemoval(BaseModel):
    hash: str
    algorithm: Algorithm
    version: int


class DeltaResponse(BaseModel):
    since: int = Field(description="The client's version, as requested.")
    until: int = Field(
        description="Version this delta brings the client to once every page is applied."
    )
    latest_version: int = Field(description="Latest version at the time of this request.")
    additions: list[DeltaAddition] = Field(description="Upsert these signatures.")
    removals: list[DeltaRemoval] = Field(description="Delete these signatures if present.")
    next_cursor: str | None = Field(
        description="Pass as `cursor` (with the same `since`) for the next page; null when done."
    )


class LookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hashes: list[Sha256Hex] = Field(
        min_length=1,
        max_length=MAX_LOOKUP_HASHES,
        description="SHA-256 digests (hex). Never send file contents.",
    )


class Verdict(BaseModel):
    hash: str
    verdict: Literal["malicious", "unknown"]
    family: str | None = None
    severity: Severity | None = None


class LookupResponse(BaseModel):
    version: int = Field(description="Signature version the verdicts are based on.")
    results: list[Verdict] = Field(description="One entry per distinct hash, in request order.")


class RulesetResponse(BaseModel):
    """A signed YARA ruleset (docs/sync-protocol.md#yara-rules)."""

    version: int = Field(description="Increases with every published ruleset.")
    sha256: str = Field(description="SHA-256 (lower-case hex) of `rules` encoded as UTF-8.")
    key_id: str = Field(description="Which trusted public key verifies `signature`.")
    signature: str = Field(
        description="Base64 DER ECDSA P-256/SHA-256 signature over "
        "`blackshield-yara-rules\n<version>\n<sha256>`."
    )
    rules: str = Field(
        description="YARA rule source; may import only the `dex` and `math` modules."
    )
    published_at: datetime


class DomainVersionResponse(BaseModel):
    version: int = Field(description="Latest published domain-list version; 0 if none.")
    created_at: datetime | None = Field(description="When that version was published.")
    count: int = Field(description="Active domains in that version.")


class DomainDeltaAddition(BaseModel):
    domain: str = Field(description="Lower-case ASCII (IDNA) name; blocks it and every subdomain.")
    category: Literal["malware", "phishing"]
    version: int


class DomainDeltaRemoval(BaseModel):
    domain: str
    version: int


class DomainDeltaResponse(BaseModel):
    since: int = Field(description="The client's version, as requested.")
    until: int = Field(description="Version this delta brings the client to once fully applied.")
    latest_version: int = Field(description="Latest version at the time of this request.")
    additions: list[DomainDeltaAddition] = Field(description="Block these domains.")
    removals: list[DomainDeltaRemoval] = Field(description="Stop blocking these domains.")
    next_cursor: str | None = Field(
        description="Pass as `cursor` (with the same `since`) for the next page; null when done."
    )
