"""Prometheus metrics, served at ``GET /metrics`` (keep it off the public internet; see
docs/backend-operations.md).

Labels are bounded: the route *template* (``/v1/signatures/delta``, never the raw path), the method
and the status code. Nothing about clients (keys, IPs, hashes) is ever a label.
"""

import logging
import time

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.models import DomainVersion, SignatureVersion, YaraRuleset

logger = logging.getLogger(__name__)

REGISTRY = CollectorRegistry(auto_describe=True)

HTTP_REQUESTS = Counter(
    "blackshield_http_requests_total",
    "HTTP requests by route template, method and status code.",
    ["route", "method", "status"],
    registry=REGISTRY,
)
HTTP_DURATION = Histogram(
    "blackshield_http_request_duration_seconds",
    "HTTP request duration by route template.",
    ["route", "method"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=REGISTRY,
)
RATE_LIMITED = Counter(
    "blackshield_rate_limited_total",
    "Requests refused with 429, by reason (rate: a valid key over its rate; auth: bad keys).",
    ["reason"],
    registry=REGISTRY,
)
AUTH_FAILURES = Counter(
    "blackshield_auth_failures_total",
    "Requests with a missing or invalid API key.",
    registry=REGISTRY,
)
CRASH_REPORTS = Counter(
    "blackshield_crash_reports_total",
    "Crash reports accepted from the app.",
    registry=REGISTRY,
)
PUBLISHED_VERSION = Gauge(
    "blackshield_published_version",
    "Latest published version per dataset (refreshed on each scrape).",
    ["dataset"],
    registry=REGISTRY,
)
ACTIVE_SIGNATURES = Gauge(
    "blackshield_active_signatures",
    "Active signatures in the latest version (refreshed on each scrape).",
    registry=REGISTRY,
)

UNMATCHED_ROUTE = "unmatched"


def observe_request(route: str | None, method: str, status: int, started: float) -> None:
    template = route or UNMATCHED_ROUTE
    HTTP_REQUESTS.labels(template, method, str(status)).inc()
    HTTP_DURATION.labels(template, method).observe(time.perf_counter() - started)


def refresh_dataset_gauges(db: Session) -> None:
    """Reads the latest published versions. A database error leaves the previous values in place."""
    try:
        PUBLISHED_VERSION.labels("signatures").set(
            db.scalar(select(func.max(SignatureVersion.version))) or 0
        )
        PUBLISHED_VERSION.labels("domains").set(
            db.scalar(select(func.max(DomainVersion.version))) or 0
        )
        PUBLISHED_VERSION.labels("yara_rules").set(
            db.scalar(select(func.max(YaraRuleset.version))) or 0
        )
        active = db.scalar(
            select(SignatureVersion.count).order_by(SignatureVersion.version.desc()).limit(1)
        )
        ACTIVE_SIGNATURES.set(active or 0)
    except SQLAlchemyError:
        logger.warning("metrics: database unavailable, dataset gauges not refreshed")


def render() -> tuple[bytes, str]:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
