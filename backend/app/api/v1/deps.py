import gzip
from dataclasses import dataclass
from typing import Annotated

from fastapi import HTTPException, Request, Response, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.core.config import Settings
from app.core.security import ApiKeyRing, RateDecision, RateLimiter

api_key_header = APIKeyHeader(
    name="X-API-Key", auto_error=False, scheme_name="ApiKey", description="BlackShield API key"
)
bearer = HTTPBearer(
    auto_error=False,
    scheme_name="Bearer",
    description="The same API key as `Authorization: Bearer <key>`",
)


@dataclass
class SecurityState:
    keys: ApiKeyRing
    limiter: RateLimiter
    auth_failures: RateLimiter

    @classmethod
    def from_settings(cls, settings: Settings) -> "SecurityState":
        return cls(
            keys=ApiKeyRing.parse(settings.api_keys),
            limiter=RateLimiter(
                per_minute=settings.rate_limit_per_minute, burst=settings.rate_limit_burst
            ),
            auth_failures=RateLimiter(
                per_minute=settings.auth_failure_limit_per_minute,
                burst=settings.auth_failure_limit_per_minute,
            ),
        )


def _too_many(decision: RateDecision) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="rate limit exceeded",
        headers={
            "Retry-After": str(decision.retry_after),
            "RateLimit-Limit": str(decision.limit),
            "RateLimit-Remaining": "0",
            "RateLimit-Reset": str(decision.retry_after),
        },
    )


def require_api_client(
    request: Request,
    api_key: Annotated[str | None, Security(api_key_header)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)],
) -> str:
    """Authenticate the API key and apply rate limits. Returns the key id."""
    security: SecurityState = request.app.state.security
    client_ip = request.client.host if request.client else "unknown"
    presented = api_key or (credentials.credentials if credentials else None)
    key_id = security.keys.verify(presented)
    if key_id is None:
        failure = security.auth_failures.hit(client_ip)
        if not failure.allowed:
            raise _too_many(failure)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid API key",
            headers={"WWW-Authenticate": 'Bearer realm="blackshield"'},
        )
    request.state.key_id = key_id
    # One key is shared by every install of an app build, so limit per key *and* client IP.
    decision = security.limiter.hit(f"{key_id}|{client_ip}")
    if not decision.allowed:
        raise _too_many(decision)
    return key_id


def accepts_gzip(request: Request) -> bool:
    for part in request.headers.get("accept-encoding", "").split(","):
        name, _, params = part.strip().partition(";")
        if name.strip().lower() not in ("gzip", "*"):
            continue
        quality = 1.0
        for param in params.split(";"):
            key, _, value = param.strip().partition("=")
            if key.strip().lower() == "q":
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0.0
        if quality > 0:
            return True
    return False


def json_response(model: BaseModel, request: Request) -> Response:
    """Serialize ``model``, gzip-compressed when the client accepts it."""
    body = model.model_dump_json().encode()
    headers = {"Vary": "Accept-Encoding"}
    if accepts_gzip(request):
        body = gzip.compress(body, compresslevel=6, mtime=0)
        headers["Content-Encoding"] = "gzip"
    return Response(content=body, media_type="application/json", headers=headers)
