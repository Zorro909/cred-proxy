"""AC-13: Logging tests."""

import logging

from auth_injection_proxy.logging import SecretMaskingFilter


class TestSecretMaskingFilter:
    def test_masks_bearer_in_message(self):
        """AC-13.3: Bearer token masked in log messages."""
        f = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Authorization: Bearer sk-secret-token-123",
            args=(),
            exc_info=None,
        )
        f.filter(record)
        assert "sk-secret-token-123" not in record.msg
        assert "Authorization: Bearer ***" in record.msg

    def test_masks_basic_in_message(self):
        """AC-13.3: Basic auth masked."""
        f = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Authorization: Basic dXNlcjpwYXNz",
            args=(),
            exc_info=None,
        )
        f.filter(record)
        assert "dXNlcjpwYXNz" not in record.msg
        assert "Authorization: Basic ***" in record.msg

    def test_masks_in_args(self):
        f = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Header: %s",
            args=("Authorization: Bearer secret123",),
            exc_info=None,
        )
        f.filter(record)
        assert "secret123" not in str(record.args)

    def test_preserves_non_auth_messages(self):
        f = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Normal log message with no secrets",
            args=(),
            exc_info=None,
        )
        f.filter(record)
        assert record.msg == "Normal log message with no secrets"

    def test_filter_always_returns_true(self):
        """Filter never suppresses records, only masks."""
        f = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None,
        )
        assert f.filter(record) is True
