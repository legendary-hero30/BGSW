"""Minimal logging. One line per event on stderr; never secrets, tokens or full tool output.

Level comes from the real environment variable GUARDIAN_LOG_LEVEL (default INFO). The .env file
is not consulted for it. Tool arguments are logged only after redaction and truncation.
"""

from __future__ import annotations

import logging
import os
import sys

from guardian.redact import redact

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def setup() -> None:
    root = logging.getLogger("guardian")
    if root.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT, "%H:%M:%S"))
    root.addHandler(handler)
    level = os.environ.get("GUARDIAN_LOG_LEVEL", "INFO").upper()
    root.setLevel(level if level in logging.getLevelNamesMapping() else "INFO")
    root.propagate = False


def short(value: object, limit: int = 100) -> str:
    """Redacted, single-line, truncated text for a log line."""
    text = " ".join(redact(str(value)).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
