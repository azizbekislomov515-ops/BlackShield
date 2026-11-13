from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.v1.deps import json_response
from app.api.v1.schemas import RulesetResponse
from app.db.session import get_db
from app.rules.store import latest_ruleset

router = APIRouter(prefix="/rules", tags=["rules"])


def ruleset_etag(version: int) -> str:
    return f'"rules-{version}"'


def _matches(if_none_match: str | None, etag: str) -> bool:
    if not if_none_match:
        return False
    candidates = [tag.strip().removeprefix("W/") for tag in if_none_match.split(",")]
    return "*" in candidates or etag in candidates


@router.get(
    "",
    response_model=RulesetResponse,
    responses={
        304: {"description": "The client already has this version (`If-None-Match`)."},
        404: {"description": "No ruleset has been published yet."},
    },
)
def latest_rules(request: Request, db: Annotated[Session, Depends(get_db)]) -> Response:
    """The latest signed YARA ruleset.

    Send the ETag of the ruleset in use as `If-None-Match` (`"rules-<version>"`): an unchanged
    ruleset costs a 304 with no body. Clients must verify `signature` with a trusted key and
    check that `rules` hashes to `sha256` before using the rules, and must ignore versions that
    are not newer than the ones they have. See docs/sync-protocol.md.
    """
    ruleset = latest_ruleset(db)
    if ruleset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="no rules published")
    etag = ruleset_etag(ruleset.version)
    # Revalidate every time (cheap with If-None-Match), so a new ruleset is seen on the next sync.
    headers = {"ETag": etag, "Cache-Control": "private, no-cache"}
    if _matches(request.headers.get("if-none-match"), etag):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    response = json_response(
        RulesetResponse(
            version=ruleset.version,
            sha256=ruleset.sha256,
            key_id=ruleset.key_id,
            signature=ruleset.signature,
            rules=ruleset.rules,
            published_at=ruleset.created_at,
        ),
        request,
    )
    response.headers.update(headers)
    return response
