"""Audit logging: every command attempt, allowed or blocked, goes to a file."""
from __future__ import annotations

import logging
import os

_loggers: dict[str, logging.Logger] = {}


def get_audit_logger(device_name: str, log_file: str | None) -> logging.Logger:
    if device_name in _loggers:
        return _loggers[device_name]

    logger = logging.getLogger(f"ssh_proxy_guard.audit.{device_name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    path = log_file or os.path.join("logs", f"{device_name}.log")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(message)s"))
    logger.addHandler(console)

    _loggers[device_name] = logger
    return logger


def log_auth(logger: logging.Logger, peer: str, username: str, ok: bool, reason: str = "") -> None:
    verdict = "AUTH_OK" if ok else "AUTH_FAIL"
    logger.info("peer=%s user=%s %s %s", peer, username, verdict, reason)


def log_command(logger: logging.Logger, peer: str, username: str, command: str, allowed: bool, reason: str) -> None:
    verdict = "ALLOWED" if allowed else "BLOCKED"
    logger.info("peer=%s user=%s %s command=%r reason=%s", peer, username, verdict, command, reason)
