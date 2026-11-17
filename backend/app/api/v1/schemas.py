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
