import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.metrics import refresh_dataset_gauges, render
from app.db.session import get_db

router = APIRouter(tags=["operations"])


@router.get("/metrics", include_in_schema=False)
def metrics(request: Request, db: Annotated[Session, Depends(get_db)]) -> Response:
    """Prometheus metrics. Disabled with METRICS_ENABLED=false. With METRICS_TOKEN set, scrapers
    must send it as a bearer token. The production Nginx config does not route /metrics from the
    internet at all."""
    settings = request.app.state.settings
    if not settings.metrics_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    token = settings.metrics_token.get_secret_value() if settings.metrics_token else ""
    if token:
        presented = request.headers.get("authorization", "")
        if not secrets.compare_digest(presented.encode(), f"Bearer {token}".encode()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    refresh_dataset_gauges(db)
    body, content_type = render()
    return Response(content=body, media_type=content_type)
