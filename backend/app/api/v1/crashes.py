import hashlib
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.api.v1.schemas import CrashReportRequest, CrashReportResponse
from app.core.metrics import CRASH_REPORTS
from app.db.models import CrashReport
from app.db.session import get_db

router = APIRouter(prefix="/crashes", tags=["crashes"])

RETENTION = timedelta(days=90)


def fingerprint(exceptions: list[str], frames: list[str]) -> str:
    """Same crash, same fingerprint: the exception chain and the frames, nothing per-device."""
    return hashlib.sha256("\n".join([*exceptions, "--", *frames]).encode()).hexdigest()


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=CrashReportResponse,
    responses={
        413: {"description": "Request body too large."},
        422: {"description": "Not a valid report."},
    },
)
def report_crash(
    body: CrashReportRequest, db: Annotated[Session, Depends(get_db)]
) -> CrashReportResponse:
    """Stores one crash report from a user who turned crash reports on.

    Only the fields in the request are kept; no IP address or other client detail is stored. Reports
    are deleted after 90 days.
    """
    now = datetime.now(UTC)
    occurred = body.occurred_at if body.occurred_at.tzinfo else body.occurred_at.replace(tzinfo=UTC)
    db.add(
        CrashReport(
            received_at=now,
            # A wrong device clock must not put reports in the future (or keep them past the
            # retention).
            occurred_at=min(occurred, now),
            app_version=body.app_version,
            version_code=body.version_code,
            android_sdk=body.android_sdk,
            exception=body.exceptions[0],
            fingerprint=fingerprint(body.exceptions, body.frames),
            stack="\n".join(["Caused by: " + name for name in body.exceptions[1:]] + body.frames),
        )
    )
    db.commit()
    CRASH_REPORTS.inc()
    return CrashReportResponse()


def prune_crash_reports(db: Session, now: datetime | None = None) -> int:
    """Deletes reports older than the retention period; returns how many."""
    cutoff = (now or datetime.now(UTC)) - RETENTION
    result = db.execute(delete(CrashReport).where(CrashReport.received_at < cutoff))
    db.commit()
    return result.rowcount or 0
