"""
Robustness and Crash-Proofing Module for PQVPN

This module provides utilities for exception handling, health checks, auto-restart,
circuit breakers, and logging enhancements to make PQVPN more robust.
"""

import json
import logging
import logging.handlers
import subprocess
import sys
import time
from collections.abc import Callable
from enum import Enum
from typing import Any


# Configure structured logging
def setup_logging(log_level: str = "INFO", log_file: str = "pqvpn.log"):
    """
    Set up structured logging with rotation.
    """
    logger = logging.getLogger("pqvpn")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Formatter for structured logs
    class ContextFormatter(logging.Formatter):
        def format(self, record):
            if hasattr(record, "context"):
                record.context = json.dumps(record.context)
            else:
                record.context = "{}"
            return super().format(record)

    formatter = ContextFormatter(
        json.dumps(
            {
                "timestamp": "%(asctime)s",
                "level": "%(levelname)s",
                "component": "%(name)s",
                "message": "%(message)s",
                "context": "%(context)s",
            }
        )
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


logger = setup_logging()


class ErrorType(Enum):
    NETWORK = "network"
    CRYPTO = "crypto"
    CONFIG = "config"
    TUN = "tun"
    GENERAL = "general"


class PQVPNError(Exception):
    def __init__(self, message: str, error_type: ErrorType, context: dict[str, Any] = None):
        super().__init__(message)
        self.error_type = error_type
        self.context = context or {}


def handle_exception(error_type: ErrorType = ErrorType.GENERAL, context: dict[str, Any] = None):
    """
    Decorator to handle exceptions in functions.
    """

    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except PQVPNError as e:
                logger.error(
                    f"PQVPN Error: {e}", extra={"context": {**e.context, **(context or {})}}
                )
                raise
            except Exception as e:
                logger.error(f"Unhandled error: {e}", extra={"context": context or {}})
                raise PQVPNError(str(e), error_type, context) from e

        return wrapper

    return decorator


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.last_exception = None
        self.state = "closed"  # closed, open, half-open

    def call(self, func: Callable, *args, **kwargs):
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half-open"
            else:
                raise self.last_exception or PQVPNError(
                    "Circuit breaker is open", ErrorType.GENERAL
                )

        try:
            result = func(*args, **kwargs)
            if self.state == "half-open":
                self.state = "closed"
                self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            self.last_exception = e
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
            raise e


circuit_breaker = CircuitBreaker()


class HealthChecker:
    def __init__(self):
        self.checks: dict[str, Callable[[], bool]] = {}
        self.metrics: dict[str, Any] = {}

    def add_check(self, name: str, check_func: Callable[[], bool]):
        self.checks[name] = check_func

    def run_checks(self) -> dict[str, bool]:
        results = {}
        for name, check in self.checks.items():
            try:
                results[name] = check()
            except Exception as e:
                logger.error(f"Health check {name} failed: {e}")
                results[name] = False
        return results

    def get_status(self) -> dict[str, Any]:
        checks = self.run_checks()
        overall = all(checks.values())
        return {"overall": overall, "checks": checks, "metrics": self.metrics}


health_checker = HealthChecker()


def auto_restart(process_name: str, command: list, max_restarts: int = 3):
    """
    Auto-restart a process with backoff.
    """
    restart_count = 0
    backoff = 1
    while restart_count < max_restarts:
        try:
            logger.info(f"Starting {process_name}")
            proc = subprocess.Popen(command)
            proc.wait()
            if proc.returncode == 0:
                break
            else:
                logger.warning(f"{process_name} exited with code {proc.returncode}, restarting")
        except Exception as e:
            logger.error(f"Failed to start {process_name}: {e}")

        restart_count += 1
        time.sleep(backoff)
        backoff *= 2

    if restart_count >= max_restarts:
        logger.error(f"Max restarts reached for {process_name}")


def log_with_context(message: str, level: str = "info", context: dict[str, Any] = None):
    """
    Log with additional context.
    """
    extra = {"context": context or {}}
    getattr(logger, level)(message, extra=extra)


# Global exception handler for unhandled exceptions
def global_exception_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.error(
        "Unhandled exception",
        extra={
            "context": {
                "exc_type": str(exc_type),
                "exc_value": str(exc_value),
                "traceback": str(exc_traceback),
            }
        },
    )


sys.excepthook = global_exception_handler
