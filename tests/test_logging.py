"""Tests for centralized logging setup."""

from __future__ import annotations

import logging

from deepscan_core import config, log


def test_get_logger_is_namespaced():
    assert log.get_logger("scanner").name == "deepscan.scanner"


def test_setup_logging_attaches_real_handler_and_level():
    log.setup_logging("DEBUG", force=True)
    root = logging.getLogger("deepscan")
    assert root.level == logging.DEBUG
    assert any(not isinstance(h, logging.NullHandler) for h in root.handlers)
    # restore a sane default for other tests
    log.setup_logging("INFO", force=True)
    assert logging.getLogger("deepscan").level == logging.INFO


def test_log_level_name_env(monkeypatch):
    monkeypatch.delenv("DEEPSCAN_DEBUG", raising=False)
    monkeypatch.delenv("DEEPSCAN_LOG_LEVEL", raising=False)
    config._dotenv_cache = {}  # bypass any .env on disk
    assert config.log_level_name() == "INFO"
    monkeypatch.setenv("DEEPSCAN_LOG_LEVEL", "warning")
    assert config.log_level_name() == "WARNING"
    monkeypatch.setenv("DEEPSCAN_DEBUG", "1")
    assert config.log_level_name() == "DEBUG"  # DEBUG toggle wins
    monkeypatch.setenv("DEEPSCAN_DEBUG", "0")
    assert config.log_level_name() == "WARNING"
