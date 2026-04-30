"""Tests for structured JSON logging + request-id middleware (PG4)."""

from __future__ import annotations

import importlib
import json
import logging

import pytest
from fastapi.testclient import TestClient

from securescan import logging_config

# ---------------------------------------------------------------------------
# JSONFormatter unit tests
# ---------------------------------------------------------------------------


def _record(msg: str = "hello", **extras) -> logging.LogRecord:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )
    for k, v in extras.items():
        setattr(record, k, v)
    return record


def test_json_formatter_emits_valid_json():
    formatter = logging_config.JSONFormatter()
    out = formatter.format(_record("hello world"))
    parsed = json.loads(out)
    assert parsed["message"] == "hello world"
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test"
    assert "ts" in parsed


def test_json_formatter_includes_extra_fields():
    formatter = logging_config.JSONFormatter()
    out = formatter.format(
        _record(
            "request",
            request_id="abc-123",
            method="GET",
            path="/api/scans",
            status=200,
            latency_ms=12.34,
        )
    )
    parsed = json.loads(out)
    assert parsed["request_id"] == "abc-123"
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/api/scans"
    assert parsed["status"] == 200
    assert parsed["latency_ms"] == 12.34


def test_json_formatter_includes_exc_info():
    formatter = logging_config.JSONFormatter()
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = logging.LogRecord("test", logging.ERROR, __file__, 1, "fail", (), sys.exc_info())
    parsed = json.loads(formatter.format(record))
    assert "exc_info" in parsed
    assert "ValueError" in parsed["exc_info"]


# ---------------------------------------------------------------------------
# configure_logging() environment resolution
# ---------------------------------------------------------------------------


def test_text_format_default_in_dev(monkeypatch):
    monkeypatch.delenv("SECURESCAN_LOG_FORMAT", raising=False)
    monkeypatch.delenv("SECURESCAN_IN_CONTAINER", raising=False)
    monkeypatch.delenv("SECURESCAN_TESTING", raising=False)
    assert logging_config._resolve_format() == "text"


def test_json_format_when_container_env_set(monkeypatch):
    monkeypatch.delenv("SECURESCAN_LOG_FORMAT", raising=False)
    monkeypatch.delenv("SECURESCAN_TESTING", raising=False)
    monkeypatch.setenv("SECURESCAN_IN_CONTAINER", "1")
    assert logging_config._resolve_format() == "json"


def test_text_format_when_testing_set(monkeypatch):
    monkeypatch.delenv("SECURESCAN_LOG_FORMAT", raising=False)
    monkeypatch.setenv("SECURESCAN_IN_CONTAINER", "1")
    monkeypatch.setenv("SECURESCAN_TESTING", "1")
    # SECURESCAN_TESTING wins over IN_CONTAINER
    assert logging_config._resolve_format() == "text"


def test_explicit_format_env_wins(monkeypatch):
    monkeypatch.setenv("SECURESCAN_LOG_FORMAT", "json")
    monkeypatch.setenv("SECURESCAN_TESTING", "1")
    monkeypatch.setenv("SECURESCAN_IN_CONTAINER", "")
    assert logging_config._resolve_format() == "json"


def test_log_level_honored(monkeypatch):
    monkeypatch.setenv("SECURESCAN_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("SECURESCAN_TESTING", "1")
    logging_config.configure_logging()
    try:
        assert logging.getLogger().level == logging.DEBUG
    finally:
        # Reset to INFO to not leak into other tests
        monkeypatch.setenv("SECURESCAN_LOG_LEVEL", "INFO")
        logging_config.configure_logging()


def test_uvicorn_access_logger_quieted(monkeypatch):
    monkeypatch.setenv("SECURESCAN_TESTING", "1")
    logging_config.configure_logging()
    assert logging.getLogger("uvicorn.access").level == logging.WARNING


def test_configure_logging_clears_old_handlers(monkeypatch):
    monkeypatch.setenv("SECURESCAN_TESTING", "1")
    sentinel = logging.NullHandler()
    logging.getLogger().addHandler(sentinel)
    logging_config.configure_logging()
    assert sentinel not in logging.getLogger().handlers


# ---------------------------------------------------------------------------
# Request-id middleware tests
# ---------------------------------------------------------------------------


@pytest.fixture
def app_client(monkeypatch):
    monkeypatch.setenv("SECURESCAN_TESTING", "1")
    monkeypatch.delenv("SECURESCAN_API_KEY", raising=False)
    main = importlib.import_module("securescan.main")
    importlib.reload(main)
    return TestClient(main.app)


def test_request_logging_middleware_assigns_request_id(app_client):
    res = app_client.get("/health")
    assert res.status_code == 200
    rid = res.headers.get("X-Request-ID")
    assert rid is not None
    assert len(rid) > 0


def test_existing_request_id_header_is_preserved(app_client):
    res = app_client.get("/health", headers={"X-Request-ID": "caller-id-abc"})
    assert res.status_code == 200
    assert res.headers.get("X-Request-ID") == "caller-id-abc"


def test_request_logging_middleware_logs_with_extras(app_client, caplog):
    caplog.set_level(logging.INFO, logger="securescan.request")
    res = app_client.get("/health")
    assert res.status_code == 200

    request_records = [r for r in caplog.records if r.name == "securescan.request"]
    assert len(request_records) >= 1
    record = request_records[-1]
    assert record.message == "request"
    assert getattr(record, "request_id", None)
    assert getattr(record, "method", None) == "GET"
    assert getattr(record, "path", None) == "/health"
    assert getattr(record, "status", None) == 200
    assert isinstance(getattr(record, "latency_ms", None), float)


def test_request_logging_middleware_logs_one_line_per_request(app_client, caplog):
    caplog.set_level(logging.INFO, logger="securescan.request")
    app_client.get("/health")
    app_client.get("/")
    request_records = [r for r in caplog.records if r.name == "securescan.request"]
    assert len(request_records) >= 2
    paths = {getattr(r, "path", None) for r in request_records}
    assert "/health" in paths
    assert "/" in paths
