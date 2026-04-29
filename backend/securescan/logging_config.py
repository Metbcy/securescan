"""Stdlib logging configured for production: JSON by default in
container, text in dev.

Reads:
  SECURESCAN_LOG_LEVEL  (default INFO)
  SECURESCAN_LOG_FORMAT (default "json" if SECURESCAN_IN_CONTAINER else "text")
  SECURESCAN_TESTING    (when set, format defaults to "text" for capsys)
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any


_STANDARD_RECORD_ATTRS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName",
})


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in (
            "request_id",
            "method",
            "path",
            "status",
            "latency_ms",
            "client",
            "api_key_hash",
        ):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False, sort_keys=True)


def _resolve_format() -> str:
    fmt = os.environ.get("SECURESCAN_LOG_FORMAT")
    if fmt is not None:
        return fmt.lower()
    if os.environ.get("SECURESCAN_TESTING"):
        return "text"
    if os.environ.get("SECURESCAN_IN_CONTAINER"):
        return "json"
    return "text"


def configure_logging() -> None:
    level = os.environ.get("SECURESCAN_LOG_LEVEL", "INFO").upper()
    fmt = _resolve_format()

    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
