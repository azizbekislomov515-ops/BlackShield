import base64
import binascii
import json
import re
import zlib
from collections.abc import Iterable, Iterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.api.v1.deps import accepts_gzip, json_response
from app.api.v1.schemas import DeltaAddition, DeltaRemoval, DeltaResponse, VersionResponse
from app.db.session import engine_dependency, get_db
from app.signatures.store import SnapshotHeader, delta_page, iter_snapshot, latest_version

router = APIRouter(prefix="/signatures", tags=["signatures"])

SNAPSHOT_FORMAT = 1
_CHUNK_BYTES = 64 * 1024
_HASH = re.compile(r"[0-9a-f]{32,64}")


class _Cursor(BaseModel):
    s: int  # since
    u: int  # until
    v: int  # version of the last row returned
    h: str  # hash of the last row returned


def encode_cursor(since: int, until: int, version: int, digest: str) -> str:
    raw = json.dumps({"s": since, "u": until, "v": version, "h": digest}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()


def decode_cursor(cursor: str) -> _Cursor:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        parsed = _Cursor.model_validate_json(raw)
    except (binascii.Error, ValueError, ValidationError):
        parsed = None
    if parsed is None or not 0 <= parsed.s < parsed.v <= parsed.u or not _HASH.fullmatch(parsed.h):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid cursor")
    return parsed


def _version_ahead(since: int, latest: int) -> HTTPException:
    return HTTPException(
        status.HTTP_409_CONFLICT,
        detail={
            "code": "version_ahead",
            "message": "the requested version is newer than the server's; run a full sync",
            "latest_version": latest,
        },
    )


@router.get("/version", response_model=VersionResponse)
def signatures_version(db: Annotated[Session, Depends(get_db)]) -> VersionResponse:
    """Latest published signature version. Clients poll this before syncing."""
    latest = latest_version(db)
    if latest is None:
        return VersionResponse(version=0, created_at=None, count=0)
    return VersionResponse(version=latest.version, created_at=latest.created_at, count=latest.count)


@router.get(
    "/delta",
    response_model=DeltaResponse,
    responses={
        400: {"description": "Invalid cursor, or cursor issued for a different `since`."},
        409: {"description": "`since` is newer than the server's latest version; full sync."},
    },
)
def signatures_delta(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    since: Annotated[int, Query(ge=0, description="The client's current version.")],
    limit: Annotated[
        int | None,
        Query(ge=1, description="Page size; defaults to 5,000 and is capped at 20,000."),
    ] = None,
    cursor: Annotated[
        str | None, Query(max_length=512, description="`next_cursor` from the previous page.")
    ] = None,
) -> Response:
    """Net additions and removals since `since`, paginated, gzip-compressed.

    Every hash appears at most once across all pages with its latest state, so a client that
    skipped any number of versions applies one delta and ends at `until`. Store `until` as the
    new local version only after the last page (`next_cursor` null) has been applied.
    """
    settings = request.app.state.settings
    page_size = min(limit or settings.delta_default_limit, settings.delta_max_limit)
    current = latest_version(db)
    latest = current.version if current else 0

    if cursor is None:
        until, after = latest, None
    else:
        decoded = decode_cursor(cursor)
        if decoded.s != since:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="cursor does not match since")
        until, after = decoded.u, (decoded.v, decoded.h)
    if since > latest or until > latest:
        raise _version_ahead(since, latest)

    rows = delta_page(db, since=since, until=until, after=after, limit=page_size + 1)
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    additions: list[DeltaAddition] = []
    removals: list[DeltaRemoval] = []
    for row in rows:
        if row.removed:
            removals.append(
                DeltaRemoval(hash=row.hash, algorithm=row.algorithm, version=row.version)
            )
        else:
            additions.append(
                DeltaAddition(
                    hash=row.hash,
                    algorithm=row.algorithm,
                    family=row.family,
                    severity=row.severity,
                    version=row.version,
                )
            )
    next_cursor = encode_cursor(since, until, rows[-1].version, rows[-1].hash) if has_more else None
    body = DeltaResponse(
        since=since,
        until=until,
        latest_version=latest,
        additions=additions,
        removals=removals,
        next_cursor=next_cursor,
    )
    return json_response(body, request)


@router.get(
    "/full",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": (
                "NDJSON stream: a header line, one line per active signature ordered by hash, "
                "and an end line. A stream without the end line is truncated; discard it."
            ),
            "content": {"application/x-ndjson": {"schema": {"type": "string"}}},
        }
    },
)
def signatures_full(
    request: Request, engine: Annotated[Engine, Depends(engine_dependency)]
) -> StreamingResponse:
    """Full snapshot of active signatures, streamed from one consistent database snapshot."""
    body: Iterator[bytes] = snapshot_ndjson(engine)
    headers = {"Vary": "Accept-Encoding"}
    if accepts_gzip(request):
        body = gzip_chunks(body)
        headers["Content-Encoding"] = "gzip"
    return StreamingResponse(body, media_type="application/x-ndjson", headers=headers)


def snapshot_ndjson(engine: Engine) -> Iterator[bytes]:
    """Encode the snapshot as NDJSON in ~64 KiB chunks. Memory use is independent of size."""
    items = iter_snapshot(engine)
    header = next(items)
    if not isinstance(header, SnapshotHeader):  # pragma: no cover - iter_snapshot contract
        raise TypeError("snapshot must start with a header")
    buffer: list[str] = [
        _line(
            {
                "type": "header",
                "format": SNAPSHOT_FORMAT,
                "version": header.version,
                "count": header.count,
                "created_at": header.created_at.isoformat() if header.created_at else None,
            }
        )
    ]
    size = len(buffer[0])
    count = 0
    for row in items:
        # hash/algorithm/severity are validated hex and enum values; only family needs escaping.
        line = (
            f'{{"hash":"{row.hash}","algorithm":"{row.algorithm}",'  # type: ignore[union-attr]
            f'"family":{json.dumps(row.family)},"severity":"{row.severity}"}}\n'  # type: ignore[union-attr]
        )
        buffer.append(line)
        size += len(line)
        count += 1
        if size >= _CHUNK_BYTES:
            yield "".join(buffer).encode()
            buffer.clear()
            size = 0
    buffer.append(_line({"type": "end", "version": header.version, "count": count}))
    yield "".join(buffer).encode()


def gzip_chunks(chunks: Iterable[bytes], level: int = 6) -> Iterator[bytes]:
    compressor = zlib.compressobj(level, zlib.DEFLATED, 31)  # wbits 31: gzip container
    for chunk in chunks:
        compressed = compressor.compress(chunk)
        if compressed:
            yield compressed
    yield compressor.flush()


def _line(obj: dict[str, Any]) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"
