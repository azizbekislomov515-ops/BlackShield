from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel

from app import __version__
from app.db.session import database_is_reachable

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str


class ReadinessResponse(BaseModel):
    status: Literal["ok", "unavailable"]
    database: Literal["ok", "unavailable"]


def get_database_check() -> Callable[[], bool]:
    return database_is_reachable


@router.get("/health")
def health() -> HealthResponse:
    """Liveness: the process is up and serving requests. Never touches the database."""
    return HealthResponse(status="ok", version=__version__)


@router.get("/health/ready", responses={503: {"model": ReadinessResponse}})
def readiness(
    response: Response,
    database_check: Annotated[Callable[[], bool], Depends(get_database_check)],
) -> ReadinessResponse:
    """Readiness: dependencies (PostgreSQL) are reachable."""
    if database_check():
        return ReadinessResponse(status="ok", database="ok")
    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status="unavailable", database="unavailable")
