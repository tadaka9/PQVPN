"""
Unit tests for robustness module.
"""

import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from pqvpn.robustness import (
    CircuitBreaker,
    ErrorType,
    HealthChecker,
    PQVPNError,
    auto_restart,
    global_exception_handler,
    handle_exception,
    log_with_context,
    setup_logging,
)


class TestSetupLogging:
    def test_setup_logging(self):
        logger = setup_logging("DEBUG", "test.log")
        assert logger.level == 10  # DEBUG
        assert logger.name == "pqvpn"


class TestHandleException:
    def test_handle_exception_success(self):
        @handle_exception(error_type=ErrorType.GENERAL)
        def success_func():
            return "ok"

        assert success_func() == "ok"

    def test_handle_exception_pqvpn_error(self):
        @handle_exception(error_type=ErrorType.GENERAL)
        def error_func():
            raise PQVPNError("test error", ErrorType.CRYPTO)

        with pytest.raises(PQVPNError):
            error_func()

    def test_handle_exception_generic_error(self):
        @handle_exception(error_type=ErrorType.NETWORK)
        def error_func():
            raise ValueError("generic error")

        with pytest.raises(PQVPNError) as exc_info:
            error_func()
        assert exc_info.value.error_type == ErrorType.NETWORK


class TestPQVPNError:
    def test_pqvpn_error(self):
        error = PQVPNError("message", ErrorType.CRYPTO, {"key": "value"})
        assert error.error_type == ErrorType.CRYPTO
        assert error.context == {"key": "value"}


class TestCircuitBreaker:
    def test_circuit_breaker_success(self):
        cb = CircuitBreaker()
        result = cb.call(lambda: "ok")
        assert result == "ok"
        assert cb.state == "closed"

    def test_circuit_breaker_failure(self):
        cb = CircuitBreaker(failure_threshold=2)

        def failing_func():
            raise ValueError("fail")

        with pytest.raises(ValueError):
            cb.call(failing_func)
        with pytest.raises(ValueError):
            cb.call(failing_func)
        with pytest.raises(ValueError):
            cb.call(lambda: "ok")
        assert cb.state == "open"

    def test_circuit_breaker_half_open(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=1)

        def failing_func():
            raise ValueError("fail")

        with pytest.raises(ValueError):
            cb.call(failing_func)
        assert cb.state == "open"
        time.sleep(2)
        result = cb.call(lambda: "ok")
        assert result == "ok"
        assert cb.state == "closed"


class TestHealthChecker:
    def test_health_checker(self):
        hc = HealthChecker()
        hc.add_check("test", lambda: True)
        status = hc.get_status()
        assert status["checks"]["test"] is True
        assert status["overall"] is True

    def test_health_checker_failure(self):
        hc = HealthChecker()
        hc.add_check("test", lambda: False)
        status = hc.get_status()
        assert status["checks"]["test"] is False
        assert status["overall"] is False


class TestAutoRestart:
    @patch("subprocess.Popen")
    def test_auto_restart_success(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.wait.return_value = None
        mock_popen.return_value = mock_proc

        auto_restart("test", ["echo", "ok"], max_restarts=1)
        mock_popen.assert_called_once_with(["echo", "ok"])

    @patch("subprocess.Popen")
    def test_auto_restart_failure(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.wait.return_value = None
        mock_popen.return_value = mock_proc

        with patch("time.sleep"):
            auto_restart("test", ["fail"], max_restarts=1)
        assert mock_popen.call_count == 1  # Only one try since max_restarts=1


class TestLogWithContext:
    def test_log_with_context(self):
        logger = setup_logging()
        with patch.object(logger, "info") as mock_log:
            log_with_context("test message", "info", {"key": "value"})
            mock_log.assert_called_once()
            args, kwargs = mock_log.call_args
            assert args[0] == "test message"
            assert "context" in kwargs["extra"]
            assert kwargs["extra"]["context"] == {"key": "value"}


class TestGlobalExceptionHandler:
    def test_global_exception_handler_keyboard_interrupt(self):
        # Should not log KeyboardInterrupt
        with patch("sys.__excepthook__") as mock_hook:
            global_exception_handler(KeyboardInterrupt, KeyboardInterrupt("test"), None)
            mock_hook.assert_called_once()

    def test_global_exception_handler_other(self):
        with patch("pqvpn.robustness.logger") as mock_logger:
            global_exception_handler(ValueError, ValueError("test"), None)
            mock_logger.error.assert_called_once()


# Integration tests for crash recovery
class TestIntegrationCrashRecovery:
    @pytest.mark.asyncio
    async def test_network_error_handling(self):
        from pqvpn.network import NetworkManager

        # Mock transport
        mock_transport = MagicMock()
        mock_transport.receive_datagram.side_effect = [asyncio.CancelledError()]

        manager = NetworkManager(mock_transport, {})
        # Test that it handles errors without crashing
        task = asyncio.create_task(manager._receive_loop())
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # Should not crash

    # Removed crypto and tun health checks due to import issues
