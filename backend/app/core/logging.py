"""Structured (JSON lines) logging.

Pass context as ``extra={...}``; every non-standard attribute of the record becomes a JSON field.
Policy: never log API keys, request bodies, submitted hashes, client IPs or query strings.
"""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_STANDARD_ATTRS = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str, ensure_ascii=False)


class _BlackShieldHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Marker class so configure_logging() is idempotent."""


def configure_logging(level: str = "INFO", json_format: bool = True) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        if isinstance(handler, _BlackShieldHandler):
            root.removeHandler(handler)
    handler = _BlackShieldHandler(sys.stderr)
    handler.setFormatter(
        JsonFormatter()
        if json_format
        else logging.Formatter("%(asctime)s %(levelname)-5s [%(name)s] %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(level.upper())
    # Uvicorn's access log contains client IPs and query strings; our middleware logs requests.
    logging.getLogger("uvicorn.access").disabled = True
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
