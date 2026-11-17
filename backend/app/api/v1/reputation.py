from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.schemas import LookupRequest, LookupResponse, Verdict
from app.db.session import get_db
from app.signatures.store import latest_version, lookup_sha256

router = APIRouter(prefix="/reputation", tags=["reputation"])


@router.post(
    "/lookup",
    response_model=LookupResponse,
    responses={413: {"description": "Request body too large."}},
)
def reputation_lookup(
    body: LookupRequest, db: Annotated[Session, Depends(get_db)]
) -> LookupResponse:
    """Verdicts for up to 100 SHA-256 digests. Submitted hashes are neither logged nor stored.

    `malicious` means the hash is an active signature. `unknown` means it is not; it does not
    mean the file is safe.
    """
    unique = list(dict.fromkeys(body.hashes))
    found = lookup_sha256(db, unique)
    current = latest_version(db)
    results = []
    for digest in unique:
        row = found.get(digest)
        if row is None:
            results.append(Verdict(hash=digest, verdict="unknown"))
        else:
            results.append(
                Verdict(hash=digest, verdict="malicious", family=row.family, severity=row.severity)
            )
    return LookupResponse(version=current.version if current else 0, results=results)
