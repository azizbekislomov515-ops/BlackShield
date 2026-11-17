from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import health
from app.api import v1 as api_v1
from app.api.v1.deps import SecurityState
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.core.middleware import BodySizeLimitMiddleware, RequestContextMiddleware

DESCRIPTION = """
Malware signature distribution for the BlackShield Android app.

* **Sync:** poll `GET /v1/signatures/version`; new installs download `GET /v1/signatures/full`,
  existing ones page through `GET /v1/signatures/delta`. See `docs/sync-protocol.md`.
* **Reputation:** `POST /v1/reputation/lookup` with up to 100 SHA-256 digests. Hashes only.
* **Auth:** every `/v1` request needs an API key in `X-API-Key` or `Authorization: Bearer`.
"""


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=DESCRIPTION,
        debug=settings.debug,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.state.settings = settings
    app.state.security = SecurityState.from_settings(settings)

    app.include_router(health.router)
    app.include_router(api_v1.router)

    # Added innermost first: request context (outermost) -> CORS -> body size limit -> app.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    if settings.cors_origins:
        # The Android app does not need CORS; only explicitly listed browser origins get it.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
            allow_credentials=False,
            max_age=600,
        )
    app.add_middleware(RequestContextMiddleware)
    return app


app = create_app()
