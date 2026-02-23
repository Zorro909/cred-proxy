"""Structured logging with secret masking."""

from __future__ import annotations

import logging
import re


class SecretMaskingFilter(logging.Filter):
    """Masks Authorization header values in log output."""

    _AUTH_RE = re.compile(r"(Authorization:\s*(?:Bearer|Basic)\s+)\S+", re.IGNORECASE)

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._AUTH_RE.sub(r"\1***", record.msg)
        if record.args:
            new_args: list[object] = []
            for arg in record.args if isinstance(record.args, tuple) else (record.args,):
                if isinstance(arg, str):
                    arg = self._AUTH_RE.sub(r"\1***", arg)
                new_args.append(arg)
            record.args = tuple(new_args)
        return True


def setup_logging() -> None:
    """Configure logging with secret masking, all output to stdout."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s — %(message)s"))
    handler.addFilter(SecretMaskingFilter())

    root = logging.getLogger("auth_injection_proxy")
    root.setLevel(logging.INFO)
    root.addHandler(handler)
