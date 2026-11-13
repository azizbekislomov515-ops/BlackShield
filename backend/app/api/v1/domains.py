import base64
import binascii
import json
import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from app.api.v1.deps import json_response
from app.api.v1.schemas import (
    DomainDeltaAddition,
    DomainDeltaRemoval,
    DomainDeltaResponse,
    DomainVersionResponse,
)
from app.db.session import get_db
from app.domains.store import domain_delta_page, latest_domain_version

router = APIRouter(prefix="/domains", tags=["domains"])

_DOMAIN = re.compile(r"[a-z0-9._-]{1,253}")


class _Cursor(BaseModel):
    s: int  # since
    u: int  # until
    v: int  # version of the last row returned
    d: str  # domain of the last row returned


def encode_cursor(since: int, until: int, version: int, domain: str) -> str:
    raw = json.dumps({"s": since, "u": until, "v": version, "d": domain}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()


def decode_cursor(cursor: str) -> _Cursor:
    try:
        parsed = _Cursor.model_validate_json(
            base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        )
    except (binascii.Error, ValueError, ValidationError):
        parsed = None
    if (
        parsed is None
        or not 0 <= parsed.s < parsed.v <= parsed.u
        or not _DOMAIN.fullmatch(parsed.d)
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid cursor")
    return parsed


@router.get("/version", response_model=DomainVersionResponse)
def domains_version(db: Annotated[Session, Depends(get_db)]) -> DomainVersionResponse:
    """Latest published domain-list version. Clients poll this before syncing."""
    latest = latest_domain_version(db)
    if latest is None:
        return DomainVersionResponse(version=0, created_at=None, count=0)
    return DomainVersionResponse(
        version=latest.version, created_at=latest.created_at, count=latest.count
    )


@router.get(
    "/delta",
    response_model=DomainDeltaResponse,
    responses={
        400: {"description": "Invalid cursor, or cursor issued for a different `since`."},
        409: {"description": "`since` is newer than the server's latest version; start from 0."},
    },
)
def domains_delta(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    since: Annotated[
        int, Query(ge=0, description="The client's current version; 0 for everything.")
    ],
    limit: Annotated[
        int | None, Query(ge=1, description="Page size; defaults to 5,000 and is capped at 20,000.")
    ] = None,
    cursor: Annotated[
        str | None, Query(max_length=1024, description="`next_cursor` from the previous page.")
    ] = None,
) -> Response:
    """Net additions and removals since `since`, paginated, gzip-compressed.

    The same protocol as `/v1/signatures/delta`: each domain appears at most once across all
    pages with its latest state; store `until` only after the last page. `since=0` returns every
    domain ever listed (removed ones as removals), which is how a client syncs the first time.
    """
    settings = request.app.state.settings
    page_size = min(limit or settings.delta_default_limit, settings.delta_max_limit)
    current = latest_domain_version(db)
    latest = current.version if current else 0
    if cursor is None:
        until, after = latest, None
    else:
        decoded = decode_cursor(cursor)
        if decoded.s != since:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="cursor does not match since")
        until, after = decoded.u, (decoded.v, decoded.d)
    if since > latest or until > latest:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "code": "version_ahead",
                "message": "the requested version is newer than the server's; sync from 0",
                "latest_version": latest,
            },
        )

    rows = domain_delta_page(db, since=since, until=until, after=after, limit=page_size + 1)
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    additions = [
        DomainDeltaAddition(domain=r.domain, category=r.category, version=r.version)
        for r in rows
        if not r.removed
    ]
    removals = [DomainDeltaRemoval(domain=r.domain, version=r.version) for r in rows if r.removed]
    next_cursor = (
        encode_cursor(since, until, rows[-1].version, rows[-1].domain) if has_more else None
    )
    return json_response(
        DomainDeltaResponse(
            since=since,
            until=until,
            latest_version=latest,
            additions=additions,
            removals=removals,
            next_cursor=next_cursor,
        ),
        request,
    )
